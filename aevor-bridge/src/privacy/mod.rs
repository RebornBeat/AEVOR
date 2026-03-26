//! Privacy-preserving bridge operations.

use serde::{Deserialize, Serialize};
pub struct CrossChainPrivacy;
pub struct SelectiveCrossChainDisclosure;
pub struct PrivacyPreservingBridge;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossChainPrivacyProof { pub proof: Vec<u8> }
