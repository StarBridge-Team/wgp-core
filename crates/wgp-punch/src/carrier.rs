//! ProbeCarrier：底层多协议抽象（00 D9，14 §8）。
//! 引擎只面向本 trait 编程；新增载体 = 新写一个实现，引擎零改动。

use std::net::SocketAddr;

/// 载体能力（能力位交换 + LinkControl::advertise_transports 的单元）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportCapability {
    Udp,
    Tcp,
    Icmp,
    Lan,
}

/// 每种协议的 NAT 映射语义（打洞预测的对象）：
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingSemantics {
    /// UDP/TCP：打端口
    PortTagged { port: u16 },
    /// ICMP Echo：打 query identifier（NAT 以 identifier 做映射）
    IdentifierTagged { id: u16 },
    /// LAN 组播：无端口语义，地址即身份
    AddrOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarrierError(pub &'static str);

/// 只要能"向目标发小包 + 收对端小包"，就能当打洞载体（14 §8）。
///
/// `send_probe` 为原生 async fn（快速路径复用调用方 executor；不进对象指针，
/// 实现方为具体类型，由引擎泛型持有）。
/// async_fn_in_trait lint 豁免：本 trait 不打对象指针，auto trait 边界无意义。
#[allow(async_fn_in_trait)]
pub trait ProbeCarrier: Send + Sync {
    /// 发送一枚探针；预算由 BudgetScheduler 预扣，本方法不做预算判断
    async fn send_probe(&self, dst: SocketAddr, payload: &[u8]) -> Result<(), CarrierError>;

    /// 收到可能是探针的包时交给引擎裁决（返回 true 表示已消费；
    /// 同步：读循环单包即可判定，无需悬挂）
    fn on_probe(&self, src: SocketAddr, payload: &[u8]) -> bool;

    /// NAT 映射语义（决定引擎如何预测/撒网）
    fn mapping_semantics(&self) -> MappingSemantics;

    /// 本载体能力标识（能力位交换用）
    fn capability(&self) -> TransportCapability;
}