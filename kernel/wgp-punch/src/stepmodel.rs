//! 端口步长模型（03 §3.4 代码化：3 次 STUN 学习建立预测窗口）。
//! 实测依据：电信/移动 CGNAT 均为"按目标分区 + 区内顺序推步"（nat/ 报告）。

/// 步长趋势
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trend {
    Increasing,
    Decreasing,
    Oscillating,
}

/// 端口步长学习模型
#[derive(Debug, Clone)]
pub struct PortStepModel {
    pub last_port: u16,
    pub mean_delta: f64,
    pub delta_range: (i32, i32),
    pub trend: Trend,
    pub confidence: f64,
}

/// 预测窗口
#[derive(Debug, Clone, Copy)]
pub struct PredictWindow {
    pub center: u16,
    pub half_width: u16,
    pub confidence: f64,
}

impl PortStepModel {
    /// 学习：至少 3 个观测端口（probes[(local_port, public_port)] 有序）
    pub fn learn(probes: &[(u16, u16)]) -> Option<Self> {
        if probes.len() < 3 {
            return None; // 历史数据不足 → 退化为宽泛探测（±3000 大撒网）
        }
        let deltas: Vec<i32> = probes
            .windows(2)
            .map(|w| w[1].1 as i32 - w[0].1 as i32)
            .collect();
        if deltas.is_empty() {
            return None;
        }
        let mean_delta = deltas.iter().sum::<i32>() as f64 / deltas.len() as f64;
        let min_delta = *deltas.iter().min().expect("非空");
        let max_delta = *deltas.iter().max().expect("非空");

        let trend = if min_delta > 0 {
            Trend::Increasing
        } else if max_delta < 0 {
            Trend::Decreasing
        } else {
            Trend::Oscillating
        };

        let variance: f64 = deltas
            .iter()
            .map(|&d| (d as f64 - mean_delta).powi(2))
            .sum::<f64>()
            / deltas.len() as f64;
        let confidence = 1.0 / (1.0 + variance / 100.0);

        Some(Self {
            last_port: probes.last().expect("非空").1,
            mean_delta,
            delta_range: (min_delta, max_delta),
            trend,
            confidence,
        })
    }

    /// 预测窗口：步长波动越大窗口越宽（00/03 §3.4.4 分层策略）
    pub fn predict_window(&self, rounds_ahead: f64) -> PredictWindow {
        let span = (self.delta_range.1 - self.delta_range.0).abs() as f64;
        let safety = 1.0 + span / 1000.0;
        let center = (self.last_port as f64 + self.mean_delta * rounds_ahead * safety)
            .round()
            .clamp(1024.0, 65535.0) as u16;
        PredictWindow {
            center,
            half_width: (50.0 * safety) as u16,
            confidence: self.confidence,
        }
    }

    /// 低置信度（<0.5）→ 调用方退化为 ±3000 大撒网
    pub fn is_reliable(&self) -> bool {
        self.confidence >= 0.5
    }

    /// 心跳步长校准更新（03 §3.7.3：cur_port - prev_port 持续校准模型）
    pub fn update_with_heartbeat(&mut self, cur_port: u16, prev_port: Option<u16>) -> bool {
        let Some(prev) = prev_port else {
            self.last_port = cur_port;
            return false;
        };
        let delta = cur_port as i32 - prev as i32;
        let expected_max = self.delta_range.0.abs().max(self.delta_range.1.abs()) * 3;
        if delta.abs() > expected_max {
            // 端口突变：连续 3 次 → confidence 归零 → 触发 STUN 重新学习
            self.confidence = 0.0;
            return true;
        }
        self.last_port = cur_port;
        let (mn, mx) = self.delta_range;
        self.delta_range = (mn.min(delta), mx.max(delta));
        false
    }
}