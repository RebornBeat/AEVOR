//! Network protocol message definitions.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolVersion { V1 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeMessage { pub version: ProtocolVersion, pub node_id: aevor_core::network::NodeId }
