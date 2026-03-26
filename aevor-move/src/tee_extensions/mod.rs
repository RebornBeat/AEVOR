//! Move language TEE service access extensions.

use serde::{Deserialize, Serialize};
use aevor_core::tee::TeePlatform;

pub struct TeeServiceModule;
pub struct ConfidentialCompute;
pub struct SecureExecution;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeContext { pub platform: TeePlatform, pub nonce: [u8; 32] }
pub type MoveTeeContext = TeeContext;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeAttestation { pub platform: TeePlatform, pub hash: aevor_core::primitives::Hash256 }
pub type MoveTeeAttestation = TeeAttestation;
