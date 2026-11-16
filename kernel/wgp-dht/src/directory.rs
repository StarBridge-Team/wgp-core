//! 种子目录（07 §5 第③层 / 17 P0）：已验签、且经存活复验的种子广告表。
//!
//! 纯数据结构，不做任何 I/O：验签、PING 复验与周期探活都在 node.rs，这里只管
//! 「一条广告该不该进、进来以后怎么更新、什么时候出去」——规则集中在一处，便于单测。
//!
//! P0 不做信任评分（17 §8 待拍板第 1 条）：任何人都能宣告。这里只挡三类低成本攻击——
//! 旧广告重放（epoch 只进不退）、谎报地址（入表前必须在所报地址上应答 PING）、
//! 用洪流挤掉用户自己配置的入口种子（pinned 条目不因容量被逐出）。

use crate::id::NodeId;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use wgp_proto::packet::{seed_advertise_v2, SeedAdvertiseV2};

/// 目录容量上限
pub const SEED_DIR_MAX: usize = 64;
/// 连续探活失败多少次后逐出
pub const SEED_MAX_FAILS: u8 = 3;

/// 广告原文（转述时逐字节保留，签名才验得过）
pub type RawAdvert = [u8; seed_advertise_v2::LEN];

/// 广告所报的 DHT 端点
pub fn advert_addr(adv: &SeedAdvertiseV2) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(adv.addr_v4), adv.dht_port))
}

/// 一个已入目录的种子
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedInfo {
    pub node_id: NodeId,
    pub pubkey: [u8; 32],
    /// DHT 信令端点（UDP）
    pub addr: SocketAddr,
    /// 观察者（STUN）端口；0 = 不提供
    pub stun_port: u16,
    /// TCP 信令端口；0 = 不提供
    pub tcp_port: u16,
    pub priority: u8,
    pub flags: u8,
    pub epoch: u64,
    /// 最近一次探活的往返耗时（毫秒）
    pub rtt_ms: Option<u32>,
}

impl SeedInfo {
    fn from_advert(node_id: NodeId, adv: &SeedAdvertiseV2, rtt_ms: Option<u32>) -> Self {
        Self {
            node_id,
            pubkey: adv.pubkey,
            addr: advert_addr(adv),
            stun_port: adv.stun_port,
            tcp_port: adv.tcp_port,
            priority: adv.priority,
            flags: adv.flags,
            epoch: adv.epoch,
            rtt_ms,
        }
    }

    /// 观察者（STUN）端点；该种子不提供观察者时为 None
    pub fn observer_addr(&self) -> Option<SocketAddr> {
        (self.stun_port != 0).then(|| SocketAddr::new(self.addr.ip(), self.stun_port))
    }

    /// TCP 信令端点；不提供时为 None
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        (self.tcp_port != 0).then(|| SocketAddr::new(self.addr.ip(), self.tcp_port))
    }

    /// 是否允许 Forward 中转（贡献模式节点为 false）
    pub fn relays(&self) -> bool {
        self.flags & seed_advertise_v2::FLAG_RELAY != 0
    }

    /// 是否支持挑战响应身份证明（17 §11）。老版本不置位：严格模式下它们无法被采信，
    /// 调用方可据此提前给出「对端需要升级」的提示，而不是等探活超时。
    pub fn supports_auth(&self) -> bool {
        self.flags & seed_advertise_v2::FLAG_AUTH_V1 != 0
    }
}

/// 一条已验签的广告相对目录现状的处置
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 不比已有的新（重放或迟到）：丢弃
    Stale,
    /// 同一端点上的更新广告：直接更新——该端点的存活由周期探活保证，不必再探
    Refresh,
    /// 新广告主，或端点变了：必须先在所报端点上探活
    Probe,
}

struct Entry {
    info: SeedInfo,
    raw: RawAdvert,
    /// 连续探活失败次数
    fails: u8,
    /// 用户显式配置的入口端点
    pinned: bool,
}

/// 种子目录
#[derive(Default)]
pub struct SeedDirectory {
    entries: HashMap<NodeId, Entry>,
}

impl SeedDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, id: &NodeId) -> Option<&SeedInfo> {
        self.entries.get(id).map(|e| &e.info)
    }

    /// 对一条已验签的广告做准入判定（不修改目录）
    pub fn judge(&self, id: &NodeId, adv: &SeedAdvertiseV2) -> Verdict {
        match self.entries.get(id) {
            Some(e) if adv.epoch <= e.info.epoch => Verdict::Stale,
            Some(e) if e.info.addr == advert_addr(adv) => Verdict::Refresh,
            _ => Verdict::Probe,
        }
    }

    /// 同端点的更新广告：替换内容，保留探活统计与 pinned 标记。
    /// 返回 false = 不适用（条目不存在、端点已变或并不更新）。
    pub fn refresh(&mut self, id: &NodeId, adv: &SeedAdvertiseV2, raw: RawAdvert) -> bool {
        if self.judge(id, adv) != Verdict::Refresh {
            return false;
        }
        if let Some(entry) = self.entries.get_mut(id) {
            entry.info = SeedInfo::from_advert(*id, adv, entry.info.rtt_ms);
            entry.raw = raw;
        }
        true
    }

    /// 写入一条探活通过的广告（新条目，或端点变更后的替换）。
    /// 返回 false = 未写入：探活期间已被更新的广告超越，或目录已满且无人可让位。
    pub fn admit(
        &mut self,
        id: NodeId,
        adv: &SeedAdvertiseV2,
        raw: RawAdvert,
        rtt_ms: Option<u32>,
        pinned: bool,
    ) -> bool {
        let addr = advert_addr(adv);
        if let Some(existing) = self.entries.get(&id) {
            if adv.epoch <= existing.info.epoch {
                return false;
            }
        }
        // 一个端点只认一个身份：探活刚证明此刻在该端点上应答的是 `id`，
        // 此前声称在同一端点的其他身份（如节点重建身份前的旧条目）已不成立
        self.entries
            .retain(|other, e| *other == id || e.info.addr != addr);
        if !self.entries.contains_key(&id)
            && self.entries.len() >= SEED_DIR_MAX
            && !self.make_room(pinned)
        {
            return false;
        }
        self.entries.insert(
            id,
            Entry {
                info: SeedInfo::from_advert(id, adv, rtt_ms),
                raw,
                fails: 0,
                pinned,
            },
        );
        true
    }

    /// 满员时腾一个位置：只有用户配置的入口种子有资格挤位，被挤的是非 pinned 条目中
    /// 探活失败最多的那个。普通广告不能挤人——否则洪流就能把诚实种子轮换出去。
    fn make_room(&mut self, newcomer_pinned: bool) -> bool {
        if !newcomer_pinned {
            return false;
        }
        let victim = self
            .entries
            .iter()
            .filter(|(_, e)| !e.pinned)
            .max_by_key(|(id, e)| (e.fails, **id))
            .map(|(id, _)| *id);
        match victim {
            Some(id) => {
                self.entries.remove(&id);
                true
            }
            None => false,
        }
    }

    /// 探活成功：清零失败计数并记录往返耗时
    pub fn mark_alive(&mut self, id: &NodeId, rtt_ms: u32) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.fails = 0;
            entry.info.rtt_ms = Some(rtt_ms);
        }
    }

    /// 探活失败：计数 +1；达到 SEED_MAX_FAILS 即逐出并返回 true。
    /// pinned 条目同样会被逐出——「入口端点」这个身份记在 node.rs 的地址集合里，
    /// 节点恢复后会被重新学到。
    pub fn mark_failed(&mut self, id: &NodeId) -> bool {
        let Some(entry) = self.entries.get_mut(id) else {
            return false;
        };
        entry.fails = entry.fails.saturating_add(1);
        if entry.fails >= SEED_MAX_FAILS {
            self.entries.remove(id);
            return true;
        }
        false
    }

    pub fn remove(&mut self, id: &NodeId) -> bool {
        self.entries.remove(id).is_some()
    }

    /// 目录快照：按往返耗时升序（未测得的排最后），相同则按 NodeId——顺序确定，便于展示与测试
    pub fn list(&self) -> Vec<SeedInfo> {
        let mut all: Vec<SeedInfo> = self.entries.values().map(|e| e.info.clone()).collect();
        all.sort_by_key(|s| (s.rtt_ms.is_none(), s.rtt_ms, s.node_id));
        all
    }

    /// 离 `target` 最近的至多 `limit` 条广告原文（Seeds 应答用）。
    /// `own` = 应答方自己的广告（若在宣告），与目录条目一起参与排序。
    /// 正在探活失败中的条目不外传：别把疑似已死的节点转述给别人去白探一次。
    pub fn closest_raw(
        &self,
        target: &NodeId,
        limit: usize,
        own: Option<(NodeId, RawAdvert)>,
    ) -> Vec<RawAdvert> {
        let mut all: Vec<(NodeId, RawAdvert)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.fails == 0)
            .map(|(id, e)| (*id, e.raw))
            .collect();
        all.extend(own);
        all.sort_by_key(|(id, _)| id.xor_distance(target));
        all.truncate(limit);
        all.into_iter().map(|(_, raw)| raw).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> NodeId {
        let mut a = [0u8; 32];
        a[0] = n;
        NodeId(a)
    }

    fn id16(n: u16) -> NodeId {
        let mut a = [0u8; 32];
        a[..2].copy_from_slice(&n.to_be_bytes());
        NodeId(a)
    }

    fn advert(host: u8, port: u16, epoch: u64) -> SeedAdvertiseV2 {
        SeedAdvertiseV2 {
            addr_v4: [10, 0, 0, host],
            dht_port: port,
            stun_port: 3478,
            tcp_port: 0,
            priority: 0,
            flags: seed_advertise_v2::FLAG_RELAY,
            epoch,
            name_hash: [0; 4],
            pubkey: [host; 32],
            signature: [0; 64],
        }
    }

    fn raw_of(adv: &SeedAdvertiseV2) -> RawAdvert {
        let mut raw = [0u8; seed_advertise_v2::LEN];
        seed_advertise_v2::encode(adv, &mut raw);
        raw
    }

    fn admit(dir: &mut SeedDirectory, who: NodeId, adv: &SeedAdvertiseV2, pinned: bool) -> bool {
        dir.admit(who, adv, raw_of(adv), Some(10), pinned)
    }

    #[test]
    fn judge_new_stale_refresh_and_moved() {
        let mut dir = SeedDirectory::new();
        let a = advert(1, 11010, 5);
        assert_eq!(dir.judge(&id(1), &a), Verdict::Probe, "新广告主必须先探活");
        assert!(admit(&mut dir, id(1), &a, false));

        assert_eq!(dir.judge(&id(1), &a), Verdict::Stale, "同 epoch = 重放");
        assert_eq!(dir.judge(&id(1), &advert(1, 11010, 4)), Verdict::Stale, "更旧 = 重放");
        assert_eq!(dir.judge(&id(1), &advert(1, 11010, 6)), Verdict::Refresh);
        // 端点变了（换 IP 或换端口）：即使 epoch 更新也要重新探活
        assert_eq!(dir.judge(&id(1), &advert(2, 11010, 6)), Verdict::Probe);
        assert_eq!(dir.judge(&id(1), &advert(1, 11011, 6)), Verdict::Probe);
        // 端点变了但 epoch 不更新：仍算重放（旧地址的旧广告不能把条目拉回去）
        assert_eq!(dir.judge(&id(1), &advert(2, 11010, 5)), Verdict::Stale);
    }

    #[test]
    fn refresh_updates_content_and_keeps_probe_stats() {
        let mut dir = SeedDirectory::new();
        assert!(admit(&mut dir, id(1), &advert(1, 11010, 5), true));
        dir.mark_alive(&id(1), 37);

        let mut newer = advert(1, 11010, 9);
        newer.stun_port = 0;
        newer.flags = 0;
        assert!(dir.refresh(&id(1), &newer, raw_of(&newer)));
        let info = dir.get(&id(1)).unwrap();
        assert_eq!(info.epoch, 9);
        assert_eq!(info.observer_addr(), None);
        assert!(!info.relays());
        assert_eq!(info.rtt_ms, Some(37), "刷新不丢探活统计");

        // 不适用的刷新一律拒绝：更旧 / 端点变了 / 条目不存在
        let older = advert(1, 11010, 8);
        assert!(!dir.refresh(&id(1), &older, raw_of(&older)));
        let moved = advert(2, 11010, 10);
        assert!(!dir.refresh(&id(1), &moved, raw_of(&moved)));
        assert!(!dir.refresh(&id(7), &newer, raw_of(&newer)));
        assert_eq!(dir.get(&id(1)).unwrap().epoch, 9);
    }

    #[test]
    fn admit_rejects_when_overtaken_during_probe() {
        let mut dir = SeedDirectory::new();
        assert!(admit(&mut dir, id(1), &advert(1, 11010, 9), false));
        // 探活期间目录已经拿到更新的广告：迟到的探活结果不得回退条目
        assert!(!admit(&mut dir, id(1), &advert(2, 11010, 8), false));
        assert_eq!(dir.get(&id(1)).unwrap().addr, advert_addr(&advert(1, 11010, 9)));
        // 端点变更 + 更新的 epoch：替换
        assert!(admit(&mut dir, id(1), &advert(2, 11010, 10), false));
        assert_eq!(dir.get(&id(1)).unwrap().addr, advert_addr(&advert(2, 11010, 10)));
        assert_eq!(dir.len(), 1);
    }

    #[test]
    fn one_endpoint_one_identity() {
        let mut dir = SeedDirectory::new();
        assert!(admit(&mut dir, id(1), &advert(1, 11010, 5), true));
        // 另一个身份在同一端点上探活通过（节点重建了身份）：旧身份立即让位
        assert!(admit(&mut dir, id(2), &advert(1, 11010, 1), false));
        assert_eq!(dir.len(), 1);
        assert!(dir.get(&id(1)).is_none());
        assert!(dir.get(&id(2)).is_some());
    }

    #[test]
    fn full_directory_only_yields_to_pinned() {
        let mut dir = SeedDirectory::new();
        for n in 0..SEED_DIR_MAX as u16 {
            let mut adv = advert((n % 250) as u8, 20_000 + n, 1);
            adv.pubkey[1] = (n >> 8) as u8;
            assert!(admit(&mut dir, id16(n + 1), &adv, false));
        }
        assert_eq!(dir.len(), SEED_DIR_MAX);

        // 普通广告：满员即拒——洪流无法把已有种子轮换出去
        assert!(!admit(&mut dir, id16(9_000), &advert(251, 40_000, 1), false));
        assert_eq!(dir.len(), SEED_DIR_MAX);

        // 用户配置的入口种子：挤掉「失败最多的非 pinned 条目」
        let shaky = id16(17);
        assert!(!dir.mark_failed(&shaky));
        assert!(admit(&mut dir, id16(9_001), &advert(252, 40_001, 1), true));
        assert_eq!(dir.len(), SEED_DIR_MAX);
        assert!(dir.get(&shaky).is_none(), "让位的应是正在探活失败的那个");
        assert!(dir.get(&id16(9_001)).is_some());
    }

    #[test]
    fn full_directory_of_pinned_refuses_everyone() {
        let mut dir = SeedDirectory::new();
        for n in 0..SEED_DIR_MAX as u16 {
            assert!(admit(&mut dir, id16(n + 1), &advert((n % 250) as u8, 20_000 + n, 1), true));
        }
        assert!(!admit(&mut dir, id16(9_000), &advert(251, 40_000, 1), true));
        assert_eq!(dir.len(), SEED_DIR_MAX);
    }

    #[test]
    fn evicted_after_consecutive_failures_only() {
        let mut dir = SeedDirectory::new();
        assert!(admit(&mut dir, id(1), &advert(1, 11010, 5), true));
        assert!(!dir.mark_failed(&id(1)));
        assert!(!dir.mark_failed(&id(1)));
        dir.mark_alive(&id(1), 12); // 中途恢复：计数清零
        assert!(!dir.mark_failed(&id(1)));
        assert!(!dir.mark_failed(&id(1)));
        assert!(dir.mark_failed(&id(1)), "连续第 3 次失败即逐出（pinned 也不例外）");
        assert!(dir.is_empty());
        assert!(!dir.mark_failed(&id(1)), "已不在目录：无事发生");
    }

    #[test]
    fn list_orders_by_rtt_then_id() {
        let mut dir = SeedDirectory::new();
        assert!(dir.admit(id(3), &advert(3, 1, 1), raw_of(&advert(3, 1, 1)), None, false));
        assert!(dir.admit(id(1), &advert(1, 1, 1), raw_of(&advert(1, 1, 1)), Some(80), false));
        assert!(dir.admit(id(2), &advert(2, 1, 1), raw_of(&advert(2, 1, 1)), Some(20), false));
        let order: Vec<NodeId> = dir.list().into_iter().map(|s| s.node_id).collect();
        assert_eq!(order, vec![id(2), id(1), id(3)]);
    }

    #[test]
    fn closest_raw_sorts_by_distance_includes_own_and_hides_failing() {
        let mut dir = SeedDirectory::new();
        for n in [0x10u8, 0x20, 0x40, 0x80] {
            assert!(admit(&mut dir, id(n), &advert(n, 11010, 1), false));
        }
        let own_adv = advert(0x30, 11010, 1);
        let own = Some((id(0x30), raw_of(&own_adv)));

        // 目标 = 0x11…：距离升序为 0x10(0x01) < 0x30(0x21) < 0x20(0x31) < 0x40 < 0x80
        let got = dir.closest_raw(&id(0x11), 3, own);
        let hosts: Vec<u8> = got.iter().map(|raw| raw[6]).collect();
        assert_eq!(hosts, vec![0x10, 0x30, 0x20]);

        // 探活失败中的条目不外传
        assert!(!dir.mark_failed(&id(0x10)));
        let got = dir.closest_raw(&id(0x11), 8, own);
        let hosts: Vec<u8> = got.iter().map(|raw| raw[6]).collect();
        assert_eq!(hosts, vec![0x30, 0x20, 0x40, 0x80]);

        // limit = 0（请求方没有填充）：一条也不给
        assert!(dir.closest_raw(&id(0x11), 0, own).is_empty());
    }
}
