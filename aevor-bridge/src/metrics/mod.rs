//! Bridge metrics.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BridgeMetrics { pub messages_relayed: u64, pub avg_relay_time_ms: u32, pub failed_relays: u64 }

impl BridgeMetrics {
    /// Success rate as a fraction (0.0–1.0). Returns 1.0 if no messages relayed.
    #[allow(clippy::cast_precision_loss)] // relay counts: u64→f64 precision loss acceptable for display ratios
    pub fn success_rate(&self) -> f64 {
        let total = self.messages_relayed + self.failed_relays;
        if total == 0 { return 1.0; }
        self.messages_relayed as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_metrics_default_zero() {
        let m = BridgeMetrics::default();
        assert_eq!(m.messages_relayed, 0);
        assert_eq!(m.failed_relays, 0);
    }

    #[test]
    fn success_rate_all_success() {
        let m = BridgeMetrics { messages_relayed: 100, avg_relay_time_ms: 50, failed_relays: 0 };
        assert!((m.success_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn success_rate_empty_is_one() {
        assert!((BridgeMetrics::default().success_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn success_rate_partial() {
        let m = BridgeMetrics { messages_relayed: 80, avg_relay_time_ms: 100, failed_relays: 20 };
        assert!((m.success_rate() - 0.8).abs() < 1e-9);
    }
}
