//! Real ML-DSA (FIPS 204) signatures via the pure-Rust `fips204` crate.
//!
//! ML-DSA-65 (NIST security category 3) is exposed here as a key pair usable
//! through the crypto-agility [`Signer`](crate::agility::Signer) trait.
//!
//! This is implemented by the vetted `fips204` crate rather than from scratch,
//! and that is the *lower-overhead, higher-performance* choice for this
//! subsystem: ML-DSA is dominated by the NTT and rejection sampling, which
//! expert implementations tune heavily (a bespoke version would be slower), and
//! lattice signing must be constant-time and NIST-vector-conformant, where a
//! hand-rolled implementation adds a large, silent side-channel risk surface.
//! `fips204` is pure Rust, so this is consistent with AEVOR's no-C++ storage
//! posture while matching how the classical primitives already rely on expert
//! crates (`ed25519-dalek`, `blst`).

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as _, Verifier as _};

/// ML-DSA-65 public key length in bytes.
pub const ML_DSA_65_PK_LEN: usize = 1952;
/// ML-DSA-65 secret key length in bytes.
pub const ML_DSA_65_SK_LEN: usize = 4032;
/// ML-DSA-65 signature length in bytes.
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// An ML-DSA-65 key pair.
pub struct MlDsa65KeyPair {
    secret: ml_dsa_65::PrivateKey,
    public_bytes: [u8; ML_DSA_65_PK_LEN],
}

impl MlDsa65KeyPair {
    /// Generate a fresh ML-DSA-65 key pair using the operating-system RNG.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKey`](crate::CryptoError::InvalidKey) if
    /// key generation fails (e.g. an RNG failure).
    pub fn generate() -> crate::CryptoResult<Self> {
        let (pk, sk) = ml_dsa_65::try_keygen().map_err(|e| crate::CryptoError::InvalidKey {
            reason: format!("ML-DSA-65 keygen failed: {e}"),
        })?;
        Ok(Self { secret: sk, public_bytes: pk.into_bytes() })
    }

    /// The public key bytes ([`ML_DSA_65_PK_LEN`] bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; ML_DSA_65_PK_LEN] {
        self.public_bytes
    }

    /// Sign `message` (with an empty ML-DSA context string).
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKey`](crate::CryptoError::InvalidKey) only
    /// in the astronomically-improbable event the internal rejection-sampling
    /// loop exhausts its iteration bound.
    pub fn sign(&self, message: &[u8]) -> crate::CryptoResult<Vec<u8>> {
        let sig = self
            .secret
            .try_sign(message, &[])
            .map_err(|e| crate::CryptoError::InvalidKey {
                reason: format!("ML-DSA-65 signing failed: {e}"),
            })?;
        Ok(sig.to_vec())
    }
}

/// Verify an ML-DSA-65 signature over `message` for the given public-key bytes.
///
/// Returns `false` on any malformed input or verification failure.
#[must_use]
pub fn verify(public_key_bytes: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk_arr): Result<[u8; ML_DSA_65_PK_LEN], _> = public_key_bytes.try_into() else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; ML_DSA_65_SIG_LEN], _> = signature.try_into() else {
        return false;
    };
    match ml_dsa_65::PublicKey::try_from_bytes(pk_arr) {
        Ok(pk) => pk.verify(message, &sig_arr, &[]),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_sizes_are_correct() {
        let kp = MlDsa65KeyPair::generate().unwrap();
        assert_eq!(kp.public_key_bytes().len(), ML_DSA_65_PK_LEN);
        let sig = kp.sign(b"hello").unwrap();
        assert_eq!(sig.len(), ML_DSA_65_SIG_LEN);
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let kp = MlDsa65KeyPair::generate().unwrap();
        let msg = b"AEVOR post-quantum transaction";
        let sig = kp.sign(msg).unwrap();
        assert!(verify(&kp.public_key_bytes(), msg, &sig));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp = MlDsa65KeyPair::generate().unwrap();
        let sig = kp.sign(b"original").unwrap();
        assert!(!verify(&kp.public_key_bytes(), b"tampered", &sig));
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let kp1 = MlDsa65KeyPair::generate().unwrap();
        let kp2 = MlDsa65KeyPair::generate().unwrap();
        let sig = kp1.sign(b"msg").unwrap();
        assert!(!verify(&kp2.public_key_bytes(), b"msg", &sig));
    }

    #[test]
    fn malformed_inputs_fail_cleanly() {
        let kp = MlDsa65KeyPair::generate().unwrap();
        let sig = kp.sign(b"msg").unwrap();
        // Wrong-length public key / signature must return false, not panic.
        assert!(!verify(&[0u8; 10], b"msg", &sig));
        assert!(!verify(&kp.public_key_bytes(), b"msg", &[0u8; 10]));
    }
}
