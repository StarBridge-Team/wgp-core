//! 载体实现集合（00 §4 四档链路：UDP / TCP / ICMP / LAN）。
//! 内核只通过这些载体建立链路；数据面协议由外围决定。

pub mod escape;
pub mod lan;
pub mod probe;
pub mod tcp;
pub mod udp;

pub use escape::IcEscape;
pub use lan::LanProbeCarrier;
pub use tcp::TcpProbeCarrier;
pub use udp::UdpProbeCarrier;