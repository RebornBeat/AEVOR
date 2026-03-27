//! Request signing: authenticate client requests with Ed25519 or BLS.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Signature;
pub use aevor_crypto::signatures::SignatureAlgorithm;

/// A signed request ready to be sent to an AEVOR node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRequest {
    /// The original request payload bytes.
    pub payload: Vec<u8>,
    /// Signature over the payload.
    pub signature: Signature,
    /// Algorithm used to produce the signature.
    pub algorithm: SignatureAlgorithm,
}

impl SignedRequest {
    /// Verify this signed request against the given public key bytes.
    pub fn verify(&self, public_key: &[u8]) -> bool {
        use aevor_crypto::signatures::Ed25519KeyPair;
        if public_key.len() != 32 { return false; }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(public_key);
        Ed25519KeyPair::verify_raw(&pk, &self.payload, &self.signature.0)
    }
}

/// An Ed25519 signing key for authenticating client requests.
///
/// Keep this secret — anyone with the signing key can authenticate as you.
pub struct SigningKey(pub [u8; 32]);

impl SigningKey {
    /// Generate a new random signing key.
    ///
    /// # Panics
    /// Panics if the OS entropy source is unavailable (catastrophic system failure).
    /// In practice this never occurs on any supported platform.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom failed");
        Self(seed)
    }

    /// Create a signing key from a raw seed (for deterministic keys, e.g. in tests).
    pub fn from_seed(seed: [u8; 32]) -> Self { Self(seed) }

    /// Return the 32-byte public key corresponding to this signing key.
    pub fn public_key(&self) -> [u8; 32] {
        use aevor_crypto::signatures::Ed25519KeyPair;
        let kp = Ed25519KeyPair::from_seed(self.0);
        kp.public_key_bytes()
    }
}

/// Signs request payloads with an `Ed25519` key.
pub struct RequestSigner;

impl RequestSigner {
    /// Sign a raw payload bytes with the given key.
    ///
    /// Returns a `SignedRequest` that can be sent to an AEVOR node.
    pub fn sign(key: &SigningKey, payload: &[u8]) -> SignedRequest {
        use aevor_crypto::signatures::Ed25519KeyPair;
        let kp = Ed25519KeyPair::from_seed(key.0);
        let sig = kp.sign(payload);
        SignedRequest {
            payload: payload.to_vec(),
            signature: sig.0,
            algorithm: SignatureAlgorithm::Ed25519,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x42u8; 32];

    #[test]
    fn signing_key_from_seed_is_deterministic() {
        let k1 = SigningKey::from_seed(SEED);
        let k2 = SigningKey::from_seed(SEED);
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn public_key_is_32_bytes_and_deterministic() {
        let key = SigningKey::from_seed(SEED);
        let pk1 = key.public_key();
        let pk2 = key.public_key();
        assert_eq!(pk1.len(), 32);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn different_seeds_produce_different_public_keys() {
        let k1 = SigningKey::from_seed([1u8; 32]);
        let k2 = SigningKey::from_seed([2u8; 32]);
        assert_ne!(k1.public_key(), k2.public_key());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = SigningKey::from_seed(SEED);
        let payload = b"hello aevor";
        let req = RequestSigner::sign(&key, payload);
        assert_eq!(req.payload, payload);
        assert!(matches!(req.algorithm, SignatureAlgorithm::Ed25519));
        // Verify with the matching public key
        let pk = key.public_key();
        assert!(req.verify(&pk));
    }

    #[test]
    fn verify_with_wrong_key_returns_false() {
        let key = SigningKey::from_seed(SEED);
        let req = RequestSigner::sign(&key, b"payload");
        let wrong_pk = SigningKey::from_seed([0xFF; 32]).public_key();
        assert!(!req.verify(&wrong_pk));
    }

    #[test]
    fn verify_with_wrong_length_key_returns_false() {
        let key = SigningKey::from_seed(SEED);
        let req = RequestSigner::sign(&key, b"payload");
        assert!(!req.verify(&[1u8; 16])); // wrong length
        assert!(!req.verify(&[]));        // empty
    }

    #[test]
    fn signing_key_generate_produces_non_zero_key() {
        let key = SigningKey::generate();
        // Vanishingly unlikely to be all zeros
        assert_ne!(key.0, [0u8; 32]);
    }
}
