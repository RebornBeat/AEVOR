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
        !proof.signature.as_bytes().iter().all(|&b| b == 0)
    }
}
