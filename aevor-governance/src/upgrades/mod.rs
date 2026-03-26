//! Protocol upgrade governance.

use serde::{Deserialize, Serialize};
pub use aevor_core::protocol::ProtocolVersion;
use aevor_core::primitives::BlockHeight;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpgradeProposal { pub new_version: ProtocolVersion, pub migration: MigrationPlan }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompatibilityProof { pub old_version: ProtocolVersion, pub new_version: ProtocolVersion, pub compatible: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpgradeActivation { pub version: ProtocolVersion, pub activation_height: BlockHeight }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationPlan { pub steps: Vec<String>, pub estimated_rounds: u64 }
