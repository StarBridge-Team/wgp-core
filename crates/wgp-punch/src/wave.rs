//! 三波探测计划生成器（03 §3.5：21+15+11，纯逻辑无 IO、零依赖，
//! 由调度器调用；发包执行与预算扣减在外层 UdpProbeCarrier/引擎）。

use crate::stepmodel::PortStepModel;
use wgp_proto::consts::{WAVE1_PACKETS, WAVE2_PACKETS, WAVE3_PACKETS};

/// 无数据模式：36 包全范围撒网（03 §3.5.2"无数据"行，无一二波）
pub const BROAD_NET_PACKETS: u16 = WAVE1_PACKETS + WAVE2_PACKETS; // 21+15=36

/// 置信度分档（03 §3.5.2 表）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// 高置信（≥0.85）：±50 精准窗口，21+15，无第三波
    High,
    /// 中置信（0.5-0.85）：±400，21+15+11
    Medium,
    /// 低置信（<0.5 有模型）/无数据：±3000 或全撒网
    Low,
}

impl From<Option<&PortStepModel>> for Confidence {
    fn from(model: Option<&PortStepModel>) -> Self {
        match model {
            None => Confidence::Low,
            Some(m) if m.confidence >= 0.85 => Confidence::High,
            Some(m) if m.confidence >= 0.5 => Confidence::Medium,
            Some(_) => Confidence::Low,
        }
    }
}

/// 三波计划（端口列表；发送顺序 wave1 → wave2 → wave3，波内按序）
#[derive(Debug, Clone)]
pub struct WavePlan {
    pub wave1: Vec<u16>,
    pub wave2: Vec<u16>,
    pub wave3: Vec<u16>,
}

impl WavePlan {
    pub fn total(&self) -> u16 {
        (self.wave1.len() + self.wave2.len() + self.wave3.len()) as u16
    }
}

/// xorshift64 确定性伪随机（可用探针 nonce 播种；避免引入第三方 RNG）
pub struct XorShift64(pub u64);

impl XorShift64 {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// 生成 [lo, hi] 内均匀整数（u16 域）
    pub fn range_u16(&mut self, lo: u16, hi: u16) -> u16 {
        let span = (hi as u32 - lo as u32 + 1) as u64;
        (lo as u64 + self.next() % span) as u16
    }
}

fn clamp_port(p: i64) -> u16 {
    p.clamp(1024, 65535) as u16
}

/// 在 [center-half, center+half] 内均匀取 n 个端口（确定性伪随机，避开外层包序聚簇）
fn sample_window(rng: &mut XorShift64, center: i64, half: i64, n: u16) -> Vec<u16> {
    (0..n)
        .map(|_| {
            let lo = (center - half).max(1024);
            let hi = (center + half).min(65535);
            if lo >= hi {
                clamp_port(center)
            } else {
                rng.range_u16(lo as u16, hi as u16)
            }
        })
        .collect()
}

/// 生成三波探测计划。
/// `packet_cap`：调度器给出的本轮可发包上限（预算裁剪在此发生，
/// 顺序裁剪：wave1 → wave2 → wave3，先保精准波）。
pub fn plan_waves(model: Option<&PortStepModel>, seed: u64, packet_cap: u16) -> WavePlan {
    let conf = Confidence::from(model);
    let max_total = packet_cap.min(
        WAVE1_PACKETS + WAVE2_PACKETS + WAVE3_PACKETS,
    );
    let mut rng = XorShift64(seed.wrapping_add(0x9E37_79B9_7F4A_7C15));

    let center = model
        .map(|m| m.predict_window(1.0).center as i64)
        .unwrap_or(0);

    match conf {
        Confidence::High => {
            // 21 包精准窗口（±50）；第二波 15 包向负方向回退（-500 窗口）
            let wave1 = sample_window(&mut rng, center, 50, WAVE1_PACKETS.min(max_total));
            let remaining = max_total.saturating_sub(wave1.len() as u16);
            let wave2 = sample_window_trunc(
                &mut rng,
                center,
                -500,
                WAVE2_PACKETS.min(remaining),
            );
            WavePlan {
                wave1,
                wave2,
                wave3: Vec::new(),
            }
        }
        Confidence::Medium => {
            let wave1 = sample_window(&mut rng, center, 400, WAVE1_PACKETS.min(max_total));
            let remaining = max_total.saturating_sub(wave1.len() as u16);
            let wave2 = sample_window_trunc(&mut rng, center, -500, WAVE2_PACKETS.min(remaining));
            let remaining = remaining.saturating_sub(wave2.len() as u16);
            let wave3 = if remaining >= WAVE3_PACKETS {
                sample_window(&mut rng, center, 3000, WAVE3_PACKETS)
            } else {
                sample_window(&mut rng, center, 3000, remaining)
            };
            WavePlan {
                wave1,
                wave2,
                wave3,
            }
        }
        Confidence::Low => {
            match model {
                Some(m) => {
                    let center = m.predict_window(1.0).center as i64;
                    let wave1 = sample_window(&mut rng, center, 3000, WAVE1_PACKETS.min(max_total));
                    let remaining = max_total.saturating_sub(wave1.len() as u16);
                    let wave2 = sample_window_trunc(&mut rng, center, -500, WAVE2_PACKETS.min(remaining));
                    let remaining = remaining.saturating_sub(wave2.len() as u16);
                    let wave3 = sample_window(&mut rng, center, 3000, remaining);
                    WavePlan {
                        wave1,
                        wave2,
                        wave3,
                    }
                }
                None => {
                    // 无数据：36 包全范围撒网（03 §3.5.2"无数据"行：无一二波）
                    let n3 = BROAD_NET_PACKETS.min(max_total);
                    let wave3 = sample_window(&mut rng, 32768, 31744, n3);
                    WavePlan {
                        wave1: Vec::new(),
                        wave2: Vec::new(),
                        wave3,
                    }
                }
            }
        }
    }
}

/// 负方向窗口采样封装：half 传负值即向 center 以下覆盖
fn sample_window_trunc(rng: &mut XorShift64, center: i64, negative_half: i64, n: u16) -> Vec<u16> {
    if n == 0 {
        return Vec::new();
    }
    let lo = (center + negative_half).max(1024);
    let hi = center.max(1024);
    if lo >= hi {
        return (0..n).map(|_| hi as u16).collect();
    }
    (0..n).map(|_| rng.range_u16(lo as u16, hi as u16)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stepmodel::{PortStepModel, Trend};

    fn model(conf: f64, last: u16) -> PortStepModel {
        PortStepModel {
            last_port: last,
            mean_delta: 5.0,
            delta_range: (2, 12),
            trend: Trend::Increasing,
            confidence: conf,
        }
    }

    #[test]
    fn high_confidence_two_waves_36() {
        let plan = plan_waves(Some(&model(0.92, 30000)), 42, 47);
        assert_eq!(plan.wave1.len(), 21);
        assert_eq!(plan.wave2.len(), 15);
        assert!(plan.wave3.is_empty());
        assert_eq!(plan.total(), 36);
        for p in plan.wave1.iter().chain(plan.wave2.iter()) {
            assert!((1024..=65535).contains(p));
        }
    }

    #[test]
    fn medium_confidence_three_waves_47() {
        let plan = plan_waves(Some(&model(0.7, 30000)), 7, 47);
        assert_eq!(plan.total(), 47);
        assert_eq!(plan.wave3.len(), 11);
    }

    #[test]
    fn no_model_broad_net_36() {
        let plan = plan_waves(None, 1, 47);
        assert_eq!(plan.total(), 36);
        for p in plan.wave1.iter().chain(plan.wave2.iter()).chain(plan.wave3.iter()) {
            assert!((1024..=65535).contains(p));
        }
    }

    #[test]
    fn budget_cap_truncates_in_order() {
        // 只给 10 包预算：wave1 被裁到 10，其后全空
        let plan = plan_waves(Some(&model(0.92, 30000)), 99, 10);
        assert_eq!(plan.wave1.len(), 10);
        assert!(plan.wave2.is_empty());
        assert!(plan.wave3.is_empty());
    }

    #[test]
    fn determinism_same_seed() {
        let a = plan_waves(Some(&model(0.7, 30000)), 12345, 47);
        let b = plan_waves(Some(&model(0.7, 30000)), 12345, 47);
        assert_eq!(a.wave1, b.wave1);
        assert_eq!(a.wave2, b.wave2);
        assert_eq!(a.wave3, b.wave3);
    }
}