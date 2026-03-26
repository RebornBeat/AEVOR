//! Faucet metrics.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FaucetMetrics { pub requests: u64, pub fulfilled: u64, pub rate_limited: u64, pub total_distributed_nano: u128 }
