//! Security metrics.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SecurityMetrics { pub threats_detected: u64, pub threats_mitigated: u64, pub slashing_events: u64 }
