//! 折跃门打洞引擎（03/04 文档的代码化）。
//! 纪律（00 §3）：调度器是唯一发包点（H6）；内核只产链路、不跑数据。

pub mod budget;
pub mod carrier;
pub mod heartbeat;
pub mod state;
pub mod stepmodel;
pub mod timer;
pub mod wave;

pub use budget::BudgetScheduler;
pub use carrier::{CarrierError, MappingSemantics, ProbeCarrier, TransportCapability};
pub use heartbeat::{HbAction, HeartbeatController, HeartbeatLoop};
pub use state::PunchState;
pub use stepmodel::{PortStepModel, Trend};
pub use timer::{DualModeTimer, TimerMode};
pub use wave::{plan_waves, Confidence, WavePlan, XorShift64};