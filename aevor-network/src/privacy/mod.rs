//! Network-layer privacy: traffic obfuscation, metadata shielding.

use serde::{Deserialize, Serialize};

/// Master switch for network privacy features.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkPrivacy { pub enabled: bool }

/// Pads all messages to a fixed size to prevent length-based traffic analysis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficObfuscation { pub pad_to_fixed_size: bool }

/// Hides the true originator of messages via onion routing or mix nets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetadataShield { pub hide_sender: bool }

/// Prevents peer list enumeration attacks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TopologyPrivacy { pub hide_peer_list: bool }

/// Adds random jitter to message delivery times to resist timing correlation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimingObfuscation { pub add_jitter_ms: u32 }
