//! Cross-chain state and proof verification.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
pub use aevor_core::consensus::FinalityProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalStateProof { pub chain: String, pub block_hash: Hash256, pub proof: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleVerification { pub root: Hash256, pub proof: Vec<u8>, pub valid: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkCrossChainProof { pub proof: Vec<u8>, pub public_inputs: Vec<Vec<u8>> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationVerification { pub attestation: Vec<u8>, pub valid: bool }

pub struct CrossChainVerifier;
impl CrossChainVerifier {
    pub fn verify_state(proof: &ExternalStateProof) -> bool { !proof.proof.is_empty() }
    pub fn verify_finality(fp: &FinalityProof) -> bool { !fp.signatures.is_empty() }
}
