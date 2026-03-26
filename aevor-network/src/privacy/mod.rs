//! Network-layer privacy: traffic obfuscation, metadata shielding.

use serde::{Deserialize, Serialize};

pub struct NetworkPrivacy { pub enabled: bool }
pub struct TrafficObfuscation { pub pad_to_fixed_size: bool }
pub struct MetadataShield { pub hide_sender: bool }
pub struct TopologyPrivacy { pub hide_peer_list: bool }
pub struct TimingObfuscation { pub add_jitter_ms: u32 }
