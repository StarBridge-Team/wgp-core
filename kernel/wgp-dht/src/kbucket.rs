//! Kademlia 路由表骨架（实现阶段补全：k-bucket 分裂、维护、SeedAdvertise 交换）。

use crate::id::NodeId;

/// Kademlia 桶容量（标准 K=20；全表上限 256*K，杜绝无界内存增长）
pub const K: usize = 20;

/// k-bucket（K=20 标准；骨架仅保留结构）
pub struct KBucket {
    pub nodes: Vec<NodeId>,
}

impl KBucket {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }
}

/// 路由表：以本节点 ID 为原点，按 XOR 距离分桶
pub struct RoutingTable {
    home: NodeId,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(home: NodeId) -> Self {
        Self {
            home,
            buckets: (0..256).map(|_| KBucket::new()).collect(),
        }
    }

    /// 节点应落入的桶号（最高不同位的位序）
    pub fn bucket_index(&self, id: &NodeId) -> usize {
        let d = self.home.xor_distance(id);
        for (i, b) in d.iter().enumerate() {
            if *b != 0 {
                let bit = b.leading_zeros() as usize;
                return i * 8 + bit;
            }
        }
        0
    }

    pub fn insert(&mut self, id: NodeId) {
        if id == self.home {
            return; // 本节点不入自己的路由表
        }
        let idx = self.bucket_index(&id);
        let bucket = &mut self.buckets[idx];
        // 重复身份：忽略（已认识者无需重新占位）
        if bucket.nodes.contains(&id) {
            return;
        }
        // K 上限：桶满拒入新客（v1 不做旧节点逐出——攻击者无法用洪流
        // 挤掉诚实节点；节点失联由上层 PING 超时清理路径兜底）
        if bucket.nodes.len() >= K {
            return;
        }
        bucket.nodes.push(id);
    }

    /// 与目标最近的 K 个已知节点（实现阶段：全表排序截断）
    pub fn closest_to(&self, target: &NodeId) -> Vec<NodeId> {
        let mut all: Vec<NodeId> = self.buckets.iter().flat_map(|b| b.nodes.iter().copied()).collect();
        all.sort_by_key(|n| {
            let d = n.xor_distance(target);
            let mut k = [0u8; 32];
            k.copy_from_slice(&d);
            k
        });
        all.truncate(K);
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte0: u8) -> NodeId {
        let mut a = [0u8; 32];
        a[0] = byte0;
        a[31] = 1;
        NodeId(a)
    }

    #[test]
    fn bucket_index_by_leading_bit() {
        let home = NodeId([0u8; 32]);
        let rt = RoutingTable::new(home);
        // 相同节点 → 0
        assert_eq!(rt.bucket_index(&home), 0);
        // 最高位差在第 7 位（0x01）→ bucket 7
        assert_eq!(rt.bucket_index(&id(0x01)), 7);
        // 最高位差在第 0 位（0x80）→ bucket 0
        assert_eq!(rt.bucket_index(&id(0x80)), 0);
        // 第二字节才差 → 8 + 7 = 15
        let mut b = [0u8; 32];
        b[1] = 0x01;
        assert_eq!(rt.bucket_index(&NodeId(b)), 15);
    }

    #[test]
    fn closest_to_sorted_by_xor_distance() {
        let home = NodeId([0u8; 32]);
        let mut rt = RoutingTable::new(home);
        let far = id(0xFF);
        let mid = id(0x08);
        let near = id(0x01);
        rt.insert(far);
        rt.insert(mid);
        rt.insert(near);
        let target = NodeId([0u8; 32]);
        let closest = rt.closest_to(&target);
        assert_eq!(closest.len(), 3);
        // 距离升序：near(1) < mid(8) < far(255)
        assert_eq!(closest[0], near);
        assert_eq!(closest[1], mid);
        assert_eq!(closest[2], far);
    }

    #[test]
    fn closest_to_truncates_to_20() {
        let home = NodeId([0u8; 32]);
        let mut rt = RoutingTable::new(home);
        for i in 0..40u8 {
            let mut a = [0u8; 32];
            a[0] = i + 1;
            rt.insert(NodeId(a));
        }
        assert_eq!(rt.closest_to(&home).len(), 20);
    }

    #[test]
    fn insert_caps_bucket_at_k() {
        let home = NodeId([0u8; 32]);
        let mut rt = RoutingTable::new(home);
        // 全部落 bucket 0（最高位差）：40 个只应留下 K=20 个
        for i in 0..40u8 {
            let mut a = [0u8; 32];
            a[0] = 0x80;
            a[31] = i;
            rt.insert(NodeId(a));
        }
        assert_eq!(rt.buckets[0].nodes.len(), K);
    }

    #[test]
    fn insert_skips_self_and_duplicates() {
        let home = NodeId([0u8; 32]);
        let mut rt = RoutingTable::new(home);
        rt.insert(home);
        let total = rt.buckets.iter().map(|b| b.nodes.len()).sum::<usize>();
        assert_eq!(total, 0, "本节点不入自己的路由表");
        let peer = id(0x10);
        rt.insert(peer);
        rt.insert(peer);
        let total = rt.buckets.iter().map(|b| b.nodes.len()).sum::<usize>();
        assert_eq!(total, 1, "重复身份不重复占位");
    }
}