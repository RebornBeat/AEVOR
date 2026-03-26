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
