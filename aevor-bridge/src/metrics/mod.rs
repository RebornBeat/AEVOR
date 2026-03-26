//! Bridge metrics.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct BridgeMetrics { pub messages_relayed: u64, pub avg_relay_time_ms: u32, pub failed_relays: u64 }
