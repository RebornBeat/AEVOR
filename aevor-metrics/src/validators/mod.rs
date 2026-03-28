//! Validator performance metrics.
use serde::{Deserialize, Serialize};
use aevor_core::primitives::ValidatorId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorMetrics { pub id: ValidatorId, pub liveness: LivenessScore, pub performance: PerformanceScore, pub tee_health: TeeHealthScore }
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LivenessScore(pub f64);
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PerformanceScore(pub f64);
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TeeHealthScore(pub f64);
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RewardRateMetric { pub validator: ValidatorId, pub rewards_per_epoch: aevor_core::primitives::Amount }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSummary { pub total: usize, pub active: usize, pub avg_liveness: f64 }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Amount, Hash256, ValidatorId};

    fn vid(n: u8) -> ValidatorId { Hash256([n; 32]) }

    #[test]
    fn validator_metrics_scores_stored() {
        let m = ValidatorMetrics { id: vid(1), liveness: LivenessScore(0.99), performance: PerformanceScore(0.95), tee_health: TeeHealthScore(1.0) };
        assert!(m.liveness.0 > 0.9);
        assert!(m.tee_health.0 > 0.9);
    }

    #[test]
    fn validator_summary_active_count() {
        let s = ValidatorSummary { total: 100, active: 87, avg_liveness: 0.98 };
        assert!(s.active < s.total);
        assert!(s.avg_liveness > 0.9);
    }
}
