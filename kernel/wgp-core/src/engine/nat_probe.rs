//! 观察者探测与 NAT 判定（15 全链路 Phase 0②/④ 的客户端侧）。
//! 用 UDP 裸 socket 向观察者发 Binding Request，解析 XOR-MAPPED 得"我的公网端点"；
//! 双观察者报告交叉 → NAT 粗判；同观察者三连测 → 步长模型（接 PortStepModel::learn）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use wgp_proto::stun::{
    decode_attrs, decode_xor_mapped, wgp_attr, binding_request, ATTR_XOR_MAPPED_ADDRESS,
    StunHeader, WgpPeerAttr,
};
use wgp_punch::PortStepModel;

/// 观察者报告的"我的公网端点"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserverReport {
    pub ipv4: [u8; 4],
    pub port: u16,
    /// 观察者回显的 nonce（与请求关联，防错勘/测量往返）
    pub echoed_nonce: Option<[u8; 8]>,
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

    /// 探测单个观察者；echo = 本次探测要回显的 WGP-PEER 扩展（None 则纯公共 STUN 档）
    pub async fn probe_observer(
        &self,
        observer: SocketAddr,
        tx_id: [u8; 12],
        echo: Option<&WgpPeerAttr>,
    ) -> Option<ObserverReport> {
        let req = binding_request(&tx_id, echo);
        self.socket.send_to(&req, observer).await.ok()?;

        let mut buf = [0u8; 512];
        let (n, _src) = tokio::time::timeout(Duration::from_millis(1500), self.socket.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        let header = StunHeader::decode(&buf[..n])?;
        if header.tx_id != tx_id {
            return None; // 非本请求的响应（乱包）
        }
        let attrs = decode_attrs(&buf[20..n])?;
        let mut mapped = None;
        let mut echoed = None;
        for (t, v) in attrs {
            match t {
                ATTR_XOR_MAPPED_ADDRESS => {
                    mapped = Some(decode_xor_mapped(&v)?);
                }
                wgp_attr::WGP_PEER => {
                    echoed = Some(WgpPeerAttr::decode(&v)?.nonce);
                }
                _ => {}
            }
        }
        let (ipv4, port) = mapped?;
        Some(ObserverReport {
            ipv4,
            port,
            echoed_nonce: echoed,
        })
    }

    /// 同观察者三连测 → 端口步长模型（接 03 §3.4 learn；样本不足返回 None）
    pub async fn learn_step(&self, observer: SocketAddr, now_fn: impl Fn() -> [u8; 8]) -> Option<PortStepModel> {
        let mut ports = Vec::with_capacity(3);
        for i in 0..3u8 {
            let mut tx_id = [0u8; 12];
            tx_id[0] = i;
            let echo = WgpPeerAttr {
                peer_prefix: [0x77; 4],
                nonce: {
                    let mut n = [0u8; 8];
                    n[0] = i;
                    n
                },
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
}