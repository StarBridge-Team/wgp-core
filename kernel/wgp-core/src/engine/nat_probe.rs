//! 观察者探测与 NAT 判定（15 全链路 Phase 0②/④ 的客户端侧）。
//! 用 UDP 裸 socket 向观察者发 Binding Request，解析 XOR-MAPPED 得"我的公网端点"；
//! 双观察者报告交叉 → NAT 粗判；同观察者三连测 → 步长模型（接 PortStepModel::learn）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use wgp_proto::stun::{
    binding_request, decode_attrs, decode_xor_mapped, wgp_attr, StunHeader, WgpPeerAttr,
    ATTR_XOR_MAPPED_ADDRESS,
};
use wgp_punch::PortStepModel;

/// 单次观察者探测的等待上限（与 DHT RPC 超时一致）
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// 观察者报告的"我的公网端点"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserverReport {
    pub ipv4: [u8; 4],
    pub port: u16,
    /// 观察者回显的 nonce（与请求关联，防错勘/测量往返）
    pub echoed_nonce: Option<[u8; 8]>,
}

/// 生成一次探测专用的 txid 与 nonce（CSPRNG）。
///
/// 为什么不能自己拼 txid：审计 M1 的投毒场景里，攻击者只要知道 txid 就能伪造/重放应答。
/// 旧实现把 txid 取成「对端 NodeId 前缀」这类可预测值，同一房间的多次探测还会重复使用；
/// nonce 更是常量。每次探测换一组随机值之后，攻击者必须先看到这一枚请求才可能拼出
/// 对应应答，观察者侧的限速与来源校验又各挡一层。
pub fn fresh_probe_ids() -> ([u8; 12], [u8; 8]) {
    use rand_core::{OsRng, RngCore};
    let mut rng = OsRng;
    let mut tx_id = [0u8; 12];
    let mut nonce = [0u8; 8];
    rng.fill_bytes(&mut tx_id);
    rng.fill_bytes(&mut nonce);
    (tx_id, nonce)
}

/// 解析一份「可能是应答」的报文，逐项校验后才承认它是本次探测的报告。
///
/// 四道绑定缺一不可：
/// 1. **消息类型**必须是 Binding Success Response——否则我们自己的请求被反射回来就能冒充应答；
/// 2. **txid** 必须与本次请求一致（关联请求与应答）；
/// 3. 请求带了 WGP-PEER（携带 nonce）时，**nonce 必须原样回显**——挡同观察者上的旧应答重放；
/// 4. 映射地址必须可用（端口非 0、地址非未指定）。
///
/// 来源地址（第 5 道）由调用方校验：本函数只看字节，便于单测覆盖每一种坏包。
pub fn parse_observer_response(
    buf: &[u8],
    tx_id: &[u8; 12],
    echo: Option<&WgpPeerAttr>,
) -> Option<ObserverReport> {
    let header = StunHeader::decode(buf)?;
    if !header.is_binding_response() {
        return None; // 反射回来的请求 / 别的 STUN 消息：不是应答
    }
    if &header.tx_id != tx_id {
        return None; // 不是本次探测
    }
    let attrs = decode_attrs(buf.get(20..)?)?;
    let mut mapped = None;
    let mut echoed: Option<[u8; 8]> = None;
    for (t, v) in attrs {
        match t {
            ATTR_XOR_MAPPED_ADDRESS => mapped = Some(decode_xor_mapped(&v)?),
            wgp_attr::WGP_PEER => echoed = Some(WgpPeerAttr::decode(&v)?.nonce),
            _ => {}
        }
    }
    if let Some(expect) = echo {
        if echoed != Some(expect.nonce) {
            return None; // 没回显我们的 nonce：旧应答 / 别人请求的应答
        }
    }
    let (ipv4, port) = mapped?;
    if port == 0 || ipv4 == [0, 0, 0, 0] {
        return None; // 畸形报告：拿它做 NAT 判定只会得到错误结论
    }
    Some(ObserverReport {
        ipv4,
        port,
        echoed_nonce: echoed,
    })
}

/// NAT 类型粗判（两个不同观察者的报告）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatClass {
    /// 两报告一致：锥形类（NAT1/2/3，或直连公网）
    ConeLike,
    /// 端口不同：疑似对称（NAT4）
    SymmetricLike,
    /// IP 出口不同：多出口/多层环境
    MultiEgress,
}

pub struct NatProbe {
    socket: Arc<UdpSocket>,
}

impl NatProbe {
    pub async fn bind() -> std::io::Result<Self> {
        Ok(Self {
            socket: Arc::new(UdpSocket::bind("0.0.0.0:0").await?),
        })
    }

    /// 复用打洞 socket（03 §3.4 核心纪律：学习与打洞同源端口，
    /// NAT 映射规律才适用于打洞本身；亦允许外围传入）
    pub fn from_socket(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// 探测单个观察者；echo = 本次探测要回显的 WGP-PEER 扩展（None 则纯公共 STUN 档）。
    ///
    /// 应答必须同时满足：**来自被探测的那个观察者地址**、类型是 Binding Success Response、
    /// txid 与本次一致、（带扩展时）nonce 原样回显。不满足的包一律当作噪声继续等——
    /// 早先的实现只看 txid，任何能抢先发出一枚同 txid 包的中间人（或把请求反射回来的反射器）
    /// 都能把「我的公网端点」写成任意值，进而把打洞引向错误地址。
    pub async fn probe_observer(
        &self,
        observer: SocketAddr,
        tx_id: [u8; 12],
        echo: Option<&WgpPeerAttr>,
    ) -> Option<ObserverReport> {
        self.probe_observer_within(observer, tx_id, echo, PROBE_TIMEOUT)
            .await
    }

    /// 同 [`Self::probe_observer`]，但显式给出等待上限（测试与运维诊断可缩短）
    pub async fn probe_observer_within(
        &self,
        observer: SocketAddr,
        tx_id: [u8; 12],
        echo: Option<&WgpPeerAttr>,
        wait: Duration,
    ) -> Option<ObserverReport> {
        let req = binding_request(&tx_id, echo);
        self.socket.send_to(&req, observer).await.ok()?;

        let deadline = Instant::now() + wait;
        let mut buf = [0u8; 512];
        loop {
            let remain = deadline.checked_duration_since(Instant::now())?;
            let (n, src) = match tokio::time::timeout(remain, self.socket.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => return None, // 超时或 socket 错误
            };
            // 第 5 道：来源必须就是所探测的观察者（UDP 源地址可伪造，但在 NAT 后面伪造
            // 一个能收到回包的源地址并不容易；这里挡的是「别的地址发来的串话/注入」）
            if src != observer {
                continue;
            }
            if let Some(report) = parse_observer_response(&buf[..n], &tx_id, echo) {
                return Some(report);
            }
            // 类型 / txid / nonce / 映射地址不符：不是本次探测的有效应答，继续等真正的那个
        }
    }

    /// 同观察者三连测 → 端口步长模型（接 03 §3.4 learn；样本不足返回 None）。
    ///
    /// 每次探测都用独立随机 txid + nonce：三连测的样本不能被彼此或旧应答串味。
    pub async fn learn_step(&self, observer: SocketAddr, now_fn: impl Fn() -> [u8; 8]) -> Option<PortStepModel> {
        let mut ports = Vec::with_capacity(3);
        for _ in 0..3u8 {
            let (tx_id, nonce) = fresh_probe_ids();
            let echo = WgpPeerAttr {
                peer_prefix: [0x77; 4],
                nonce,
                timestamp: now_fn(),
                flags: [0; 4],
            };
            let report = self.probe_observer(observer, tx_id, Some(&echo)).await?;
            ports.push(report.port);
        }
        let samples: Vec<(u16, u16)> = ports.iter().map(|&p| (0, p)).collect();
        PortStepModel::learn(&samples)
    }
}

/// 双观察者交叉判定
pub fn classify_reports(a: &ObserverReport, b: &ObserverReport) -> NatClass {
    if a.ipv4 != b.ipv4 {
        return NatClass::MultiEgress;
    }
    if a.port == b.port {
        NatClass::ConeLike
    } else {
        NatClass::SymmetricLike
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wgp_dht::ObserverServer;

    fn observer_addr(server: &std::sync::Arc<ObserverServer>) -> SocketAddr {
        format!("127.0.0.1:{}", server.local_addr().unwrap().port())
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn cone_like_on_loopback_dual_observers() {
        let obs_a = ObserverServer::bind(0).await.unwrap();
        let obs_b = ObserverServer::bind(0).await.unwrap();
        let probe = NatProbe::bind().await.unwrap();

        let report_a = probe
            .probe_observer(observer_addr(&obs_a), [0x01; 12], None)
            .await
            .expect("观察者 A 应报告");
        let report_b = probe
            .probe_observer(observer_addr(&obs_b), [0x02; 12], None)
            .await
            .expect("观察者 B 应报告");

        // loopback 无 NAT：同一 socket 对两个观察者端口一致 → ConeLike
        assert_eq!(report_a.port, report_b.port);
        assert_eq!(classify_reports(&report_a, &report_b), NatClass::ConeLike);
    }

    #[tokio::test]
    async fn echo_roundtrip_nonce_match() {
        let obs = ObserverServer::bind(0).await.unwrap();
        let probe = NatProbe::bind().await.unwrap();
        let my_nonce = [9, 8, 7, 6, 5, 4, 3, 2];
        let echo = WgpPeerAttr {
            peer_prefix: [1, 2, 3, 4],
            nonce: my_nonce,
            timestamp: [0; 8],
            flags: [0; 4],
        };
        let report = probe
            .probe_observer(observer_addr(&obs), [0x03; 12], Some(&echo))
            .await
            .expect("带扩展探测应成功");
        assert_eq!(report.echoed_nonce, Some(my_nonce), "nonce 必须回显");
    }

    #[tokio::test]
    async fn step_learning_three_probes() {
        let obs = ObserverServer::bind(0).await.unwrap();
        let probe = NatProbe::bind().await.unwrap();
        let model = probe
            .learn_step(observer_addr(&obs), || [0u8; 8])
            .await
            .expect("3 次样本应可学");
        // loopback 步长恒 0 → 置信度极高
        assert!(model.confidence > 0.9);
        assert_eq!(model.mean_delta, 0.0);
    }

    #[tokio::test]
    async fn dead_observer_times_out() {
        let probe = NatProbe::bind().await.unwrap();
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = probe.probe_observer(dead, [0x04; 12], None).await;
        assert!(r.is_none(), "死观察者必须超时返回 None");
    }

    // —— 审计 M1：STUN 响应绑定与投毒防护 ——————————————————————

    use wgp_proto::stun::{binding_response, BINDING_REQUEST};

    fn echo_attr(nonce: [u8; 8]) -> WgpPeerAttr {
        WgpPeerAttr {
            peer_prefix: [1, 2, 3, 4],
            nonce,
            timestamp: [0; 8],
            flags: [0; 4],
        }
    }

    /// 起一个「假观察者」：收到探测后按闭包构造应答回给来源（返回 None 则不应答）
    async fn fake_observer<F>(reply: F) -> SocketAddr
    where
        F: Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static,
    {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, src)) = sock.recv_from(&mut buf).await {
                if let Some(resp) = reply(&buf[..n]) {
                    let _ = sock.send_to(&resp, src).await;
                }
            }
        });
        addr
    }

    fn txid_of(req: &[u8]) -> [u8; 12] {
        let mut tx = [0u8; 12];
        tx.copy_from_slice(&req[8..20]);
        tx
    }

    /// 逐项校验矩阵：类型 / txid / nonce / 畸形映射地址任一不符都不能成为报告
    #[test]
    fn response_binding_matrix() {
        let txid = [0x42u8; 12];
        let nonce = [7u8; 8];
        let echo = echo_attr(nonce);
        let good = binding_response(&txid, [203, 0, 113, 9], 41107, Some(&echo));
        let ok = parse_observer_response(&good, &txid, Some(&echo)).expect("合法应答应通过");
        assert_eq!((ok.ipv4, ok.port), ([203, 0, 113, 9], 41107));
        assert_eq!(ok.echoed_nonce, Some(nonce));

        // 1）类型：把我们自己的请求（同 txid、同 cookie）反射回来 → 不是应答
        let mut reflected = good.clone();
        reflected[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        assert!(parse_observer_response(&reflected, &txid, Some(&echo)).is_none());

        // 2）txid 不符：别人请求的应答
        let other = [0x43u8; 12];
        assert!(parse_observer_response(&good, &other, Some(&echo)).is_none());

        // 3）nonce 未回显 / 回显了别的 nonce：旧应答重放
        let wrong_nonce = binding_response(&txid, [203, 0, 113, 9], 41107, Some(&echo_attr([8u8; 8])));
        assert!(parse_observer_response(&wrong_nonce, &txid, Some(&echo)).is_none());
        let no_echo = binding_response(&txid, [203, 0, 113, 9], 41107, None);
        assert!(parse_observer_response(&no_echo, &txid, Some(&echo)).is_none());
        // 纯公共 STUN 档（请求没带扩展）：不要求回显
        assert!(parse_observer_response(&no_echo, &txid, None).is_some());

        // 4）畸形映射地址：端口 0 / 未指定地址
        let zero_port = binding_response(&txid, [203, 0, 113, 9], 0, Some(&echo));
        assert!(parse_observer_response(&zero_port, &txid, Some(&echo)).is_none());
        let zero_ip = binding_response(&txid, [0, 0, 0, 0], 41107, Some(&echo));
        assert!(parse_observer_response(&zero_ip, &txid, Some(&echo)).is_none());

        // 5）垃圾 / 截断
        assert!(parse_observer_response(&[0u8; 4], &txid, None).is_none());
        assert!(parse_observer_response(&good[..24], &txid, Some(&echo)).is_none());
    }

    /// 投毒：另一台主机（源地址不符）抢先/持续发来「同 txid 的合法应答」——
    /// 必须被忽略，最终报告仍是真观察者给出的那个映射。
    #[tokio::test]
    async fn forged_reply_from_other_source_is_ignored() {
        let obs = ObserverServer::bind(0).await.unwrap();
        let observer = observer_addr(&obs);
        let probe = NatProbe::bind().await.unwrap();
        let client_addr = probe.socket().local_addr().unwrap();

        // 攻击者知道 txid（旧实现里 txid 取自对端 NodeId 前缀，完全可预测）
        let txid = [0x5Au8; 12];
        let rogue = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forged = binding_response(&txid, [6, 6, 6, 6], 6666, None);
        let rogue_task = tokio::spawn(async move {
            for _ in 0..80 {
                let _ = rogue.send_to(&forged, client_addr).await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let report = probe
            .probe_observer_within(observer, txid, None, Duration::from_millis(1200))
            .await
            .expect("真观察者应给出报告");
        rogue_task.abort();

        assert_ne!(report.ipv4, [6, 6, 6, 6], "伪造来源的应答不得被采信");
        assert_ne!(report.port, 6666, "伪造来源的应答不得被采信");
        assert_eq!(report.ipv4, [127, 0, 0, 1]);
    }

    /// 一个「观察者」回了 txid 正确但不回显 nonce 的应答：不能据此得出我的公网端点
    #[tokio::test]
    async fn observer_that_does_not_echo_nonce_is_rejected() {
        let fake = fake_observer(|req: &[u8]| {
            let txid = txid_of(req);
            Some(binding_response(&txid, [203, 0, 113, 9], 41107, None))
        })
        .await;
        let probe = NatProbe::bind().await.unwrap();
        let echo = echo_attr([1, 2, 3, 4, 5, 6, 7, 8]);
        let r = probe
            .probe_observer_within(fake, [0x11; 12], Some(&echo), Duration::from_millis(400))
            .await;
        assert!(r.is_none(), "未回显 nonce 的应答必须被拒绝");
    }

    /// 反射器：把我们发出去的请求原样弹回（同 txid 同 cookie，只有类型不同）→ 不是报告
    #[tokio::test]
    async fn reflected_request_is_not_a_report() {
        let fake = fake_observer(|req: &[u8]| Some(req.to_vec())).await;
        let probe = NatProbe::bind().await.unwrap();
        let r = probe
            .probe_observer_within(fake, [0x12; 12], None, Duration::from_millis(400))
            .await;
        assert!(r.is_none(), "反射回来的请求不能被当成映射报告");
    }
}