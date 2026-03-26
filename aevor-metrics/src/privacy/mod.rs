//! Privacy-preserving metrics (infrastructure only, no user surveillance).
use serde::{Deserialize, Serialize};
/// Differential privacy noise level for metric aggregation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct DifferentialPrivacyConfig { pub epsilon: f64, pub sensitivity: f64 }
impl Default for DifferentialPrivacyConfig {
    fn default() -> Self { Self { epsilon: 1.0, sensitivity: 1.0 } }
}
