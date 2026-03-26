//! Consensus metrics.
use serde::{Deserialize, Serialize};
use aevor_core::consensus::SecurityLevel;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusMetrics { pub rounds: u64, pub avg_duration_ms: f64, pub security_level: SecurityLevel }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundDuration { pub round: u64, pub duration_ms: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityLevelDistribution { pub minimal_pct: f64, pub basic_pct: f64, pub strong_pct: f64, pub full_pct: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityLatency { pub avg_ms: f64, pub p99_ms: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusSummary { pub total_rounds: u64, pub avg_participation_pct: f64 }
