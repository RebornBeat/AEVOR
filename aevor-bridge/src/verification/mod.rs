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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, ValidatorWeight};
    use aevor_core::consensus::{FinalityProof, SecurityLevel};

    fn state_proof(chain: &str, nonempty: bool) -> ExternalStateProof {
        ExternalStateProof { chain: chain.into(), block_hash: Hash256::ZERO, proof: if nonempty { vec![1,2,3] } else { vec![] } }
    }

    fn finality_proof_empty() -> FinalityProof {
        FinalityProof { signatures: vec![], aggregate_signature: vec![], participant_bitmap: vec![], total_weight: ValidatorWeight::from_u64(0), security_level: SecurityLevel::Basic }
    }

    #[test]
    fn verify_state_accepts_nonempty_proof() {
        assert!(CrossChainVerifier::verify_state(&state_proof("ethereum", true)));
    }

    #[test]
    fn verify_state_rejects_empty_proof() {
        assert!(!CrossChainVerifier::verify_state(&state_proof("bitcoin", false)));
    }

    #[test]
    fn verify_finality_rejects_empty_signatures() {
        assert!(!CrossChainVerifier::verify_finality(&finality_proof_empty()));
    }

    #[test]
    fn merkle_verification_stores_validity() {
        let mv = MerkleVerification { root: Hash256::ZERO, proof: vec![1], valid: true };
        assert!(mv.valid);
    }

    #[test]
    fn zk_cross_chain_proof_stores_inputs() {
        let p = ZkCrossChainProof { proof: vec![0xAB; 32], public_inputs: vec![vec![1,2,3]] };
        assert_eq!(p.public_inputs.len(), 1);
        assert!(!p.proof.is_empty());
    }
}
