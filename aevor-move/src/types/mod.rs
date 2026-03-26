//! AEVOR-extended Move types.

use serde::{Deserialize, Serialize};
use aevor_core::privacy::PrivacyLevel;
use aevor_core::tee::TeePlatform;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyType { pub inner: String, pub level: PrivacyLevel }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeType { pub inner: String, pub platform: Option<TeePlatform> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationType { pub inner: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossChainType { pub inner: String, pub chain: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AevorMoveType {
    Privacy(PrivacyType), Tee(TeeType), Attestation(AttestationType),
    CrossChain(CrossChainType), Standard(String),
}
