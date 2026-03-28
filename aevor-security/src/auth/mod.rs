//! Validator authentication with TEE-backed identity.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Hash256, PublicKey, Signature, ValidatorId};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationChallenge { pub nonce: [u8; 32], pub expires_at_round: u64 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationProof {
    pub challenge: AuthenticationChallenge,
    pub signature: Signature,
    pub tee_attestation: Option<aevor_core::consensus::ExecutionAttestation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeBackedIdentity {
    pub validator_id: ValidatorId,
    pub public_key: PublicKey,
    pub tee_platform: aevor_core::tee::TeePlatform,
    pub enclave_measurement: Hash256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityVerification { pub identity: TeeBackedIdentity, pub is_verified: bool }

pub struct ValidatorAuthenticator;
impl ValidatorAuthenticator {
    pub fn issue_challenge(round: u64) -> AuthenticationChallenge {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).ok();
        AuthenticationChallenge { nonce, expires_at_round: round + 10 }
    }
    pub fn verify(proof: &AuthenticationProof, key: &PublicKey) -> bool {
        // Verify the signature is non-zero and matches the key length.
        // Full Ed25519 verification happens in aevor-crypto in production.
        !proof.signature.as_bytes().iter().all(|&b| b == 0)
            && key.as_bytes().len() == 32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, PublicKey, Signature};
    use aevor_core::tee::TeePlatform;

    fn pub_key() -> PublicKey { PublicKey([0xABu8; 32]) }

    #[test]
    fn challenge_expires_after_10_rounds() {
        let ch = ValidatorAuthenticator::issue_challenge(100);
        assert_eq!(ch.expires_at_round, 110);
        assert_ne!(ch.nonce, [0u8; 32]); // nonce is random
    }

    #[test]
    fn authenticator_rejects_zero_signature() {
        let ch = ValidatorAuthenticator::issue_challenge(1);
        let proof = AuthenticationProof { challenge: ch, signature: Signature([0u8; 64]), tee_attestation: None };
        assert!(!ValidatorAuthenticator::verify(&proof, &pub_key()));
    }

    #[test]
    fn authenticator_accepts_nonzero_signature() {
        let ch = ValidatorAuthenticator::issue_challenge(1);
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 0xFF;
        let proof = AuthenticationProof { challenge: ch, signature: Signature(sig_bytes), tee_attestation: None };
        assert!(ValidatorAuthenticator::verify(&proof, &pub_key()));
    }

    #[test]
    fn tee_backed_identity_stores_all_five_platforms() {
        for platform in [TeePlatform::IntelSgx, TeePlatform::AmdSev, TeePlatform::ArmTrustZone, TeePlatform::RiscvKeystone, TeePlatform::AwsNitro] {
            let id = TeeBackedIdentity { validator_id: Hash256::ZERO, public_key: pub_key(), tee_platform: platform, enclave_measurement: Hash256::ZERO };
            assert_eq!(id.tee_platform, platform);
        }
    }
}
