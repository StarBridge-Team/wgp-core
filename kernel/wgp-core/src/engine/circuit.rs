//! T1-T4 触发判定（00 §4 TCP 兜底触发条件表）。
//! 竞速模型下 T2/T3 天然由并行兜底覆盖（TCP 同步在跑）；
//! 本模块负责"预判类"决策：T1（UDP 出站不可用 → 跳过 UDP 路径）、
//! T4（运营商画像差 + 对端同意 → 仍按并行但降 UDP 权重）。
//! T3（QUIC 握手超时）在 QUIC 接入阶段启用。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TcpTrigger {
    /// T1：任一侧确认 UDP 出站不可用（预判层）
    UdpBlocked,
    /// T2：UDP 三波全灭（竞速兜底层，事后判定）
    UdpWavesFailed,
    /// T3：UDP 打通但 QUIC 握手超时（疑 DPI 拦 QUIC）
    QuicHandshakeTimeout,
    /// T4：运营商画像显示 UDP 高丢包 + 对端同意切换
    CarrierProfile,
}

#[derive(Debug, Clone, Copy)]
pub struct CircuitInput {
    /// 本端 UDP 出站可用性（None = 未测；观察者/公共 STUN 预判产出）
    pub udp_egress_ok: Option<bool>,
    /// 对端宣告（承诺-揭示阶段能力位）
    pub peer_udp_ok: Option<bool>,
    /// UDP 三波已全灭（竞速结果回填）
    pub udp_waves_failed: bool,
    /// UDP 通但 QUIC 握手超时（Phase 6 后半启用）
    pub quic_handshake_timed_out: bool,
    /// D2 运营商画像：UDP 信道质量差
    pub carrier_profile_bad: bool,
    /// 能力位协商：对端同意走 TCP
    pub peer_agrees_tcp: bool,
}

impl Default for CircuitInput {
    fn default() -> Self {
        Self {
            udp_egress_ok: None,
            peer_udp_ok: None,
            udp_waves_failed: false,
            quic_handshake_timed_out: false,
            carrier_profile_bad: false,
            peer_agrees_tcp: false,
        }
    }
}

impl CircuitInput {
    /// 判定当前是否已命中任一 TCP 触发条件（优先级 T1 > T2 > T3 > T4）
    pub fn tcp_triggered(&self) -> Option<TcpTrigger> {
        if self.udp_egress_ok == Some(false) || self.peer_udp_ok == Some(false) {
            return Some(TcpTrigger::UdpBlocked);
        }
        if self.udp_waves_failed {
            return Some(TcpTrigger::UdpWavesFailed);
        }
        if self.quic_handshake_timed_out {
            return Some(TcpTrigger::QuicHandshakeTimeout);
        }
        if self.carrier_profile_bad && self.peer_agrees_tcp {
            return Some(TcpTrigger::CarrierProfile);
        }
        None
    }
}

/// 竞速路径配置：预判层决定是否跳过 UDP 路径（T1 命中即纯 TCP）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaceConfig {
    pub udp_on: bool,
    pub tcp_on: bool,
}

pub fn decide_race(circuit: &CircuitInput, tcp_available: bool) -> RaceConfig {
    let udp_blocked = circuit.udp_egress_ok == Some(false) || circuit.peer_udp_ok == Some(false);
    RaceConfig {
        udp_on: !udp_blocked,
        tcp_on: tcp_available && (udp_blocked || circuit.carrier_profile_bad && circuit.peer_agrees_tcp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t1_udp_blocked_wins_priority() {
        let mut c = CircuitInput::default();
        c.udp_egress_ok = Some(false);
        c.udp_waves_failed = true;
        assert_eq!(c.tcp_triggered(), Some(TcpTrigger::UdpBlocked));
    }

    #[test]
    fn t1_via_peer_declaration() {
        let mut c = CircuitInput::default();
        c.peer_udp_ok = Some(false);
        assert_eq!(c.tcp_triggered(), Some(TcpTrigger::UdpBlocked));
    }

    #[test]
    fn t2_then_t3_then_t4_order() {
        let mut c = CircuitInput::default();
        c.udp_waves_failed = true;
        assert_eq!(c.tcp_triggered(), Some(TcpTrigger::UdpWavesFailed));
        c.udp_waves_failed = false;
        c.quic_handshake_timed_out = true;
        assert_eq!(c.tcp_triggered(), Some(TcpTrigger::QuicHandshakeTimeout));
        c.quic_handshake_timed_out = false;
        c.carrier_profile_bad = true;
        assert_eq!(c.tcp_triggered(), None, "对端未同意不得触发 T4");
        c.peer_agrees_tcp = true;
        assert_eq!(c.tcp_triggered(), Some(TcpTrigger::CarrierProfile));
    }

    #[test]
    fn race_config_skips_udp_on_t1() {
        let mut c = CircuitInput::default();
        c.udp_egress_ok = Some(false);
        let cfg = decide_race(&c, true);
        assert!(!cfg.udp_on && cfg.tcp_on);
    }

    #[test]
    fn race_config_full_race_when_no_trigger() {
        let cfg = decide_race(&CircuitInput::default(), true);
        assert!(cfg.udp_on);
        assert!(!cfg.tcp_on, "无触发且仅并行默认：TCP 由竞速层自带（此处仅预判）");
    }
}