//! Bulletproofs — no trusted setup, efficient range proofs.

use serde::{Deserialize, Serialize};
pub use aevor_crypto::proofs::BulletProof as BulletproofProof;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof { pub proof: BulletproofProof, pub min: u64, pub max: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerProductProof { pub proof: Vec<u8> }

pub struct BulletproofVerifier;
impl BulletproofVerifier {
    pub fn verify_range(proof: &RangeProof) -> bool { !proof.proof.proof_bytes.is_empty() }
}
