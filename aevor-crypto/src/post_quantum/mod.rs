//! Post-quantum hybrid schemes: Ed25519 + CRYSTALS-Dilithium.
//!
//! Classical algorithms remain primary for performance; PQ algorithms
//! provide cryptographic agility for future-proofing.

/// Real ML-DSA (FIPS 204) signatures.
pub mod ml_dsa;

pub use ml_dsa::MlDsa65KeyPair;

use serde::{Deserialize, Serialize};

/// Quantum resistance level of a cryptographic construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuantumResistanceLevel {
    /// Classical security only (Ed25519 / BLS12-381).
    Classical,
    /// Hybrid: classical + post-quantum signature.
    Hybrid,
    /// Post-quantum only (reserved for future use).
    PostQuantumOnly,
}

/// A CRYSTALS-Dilithium public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DilithiumPublicKey(pub Vec<u8>);

/// A CRYSTALS-Dilithium signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DilithiumSignature(pub Vec<u8>);

/// A hybrid signature: Ed25519 (classical) combined with Dilithium (post-quantum).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical Ed25519 signature component.
    pub classical: crate::signatures::Ed25519Signature,
    /// Post-quantum Dilithium signature component.
    pub post_quantum: DilithiumSignature,
    /// Quantum resistance level of this signature.
    pub level: QuantumResistanceLevel,
}

impl HybridSignature {
    /// Returns `true` if this signature includes a post-quantum component.
    pub fn is_post_quantum(&self) -> bool {
        !matches!(self.level, QuantumResistanceLevel::Classical)
    }
}

/// Hybrid key pair: Ed25519 + ML-DSA-65 (both real).
///
/// The post-quantum component is real ML-DSA-65 via the vetted `fips204` crate
/// (see `ml_dsa.rs`); the classical component is real Ed25519. A hybrid
/// signature is valid only if *both* components verify, so the account stays
/// secure as long as either primitive remains unbroken.
pub struct HybridKeyPair {
    classical: crate::signatures::Ed25519KeyPair,
    pq: crate::post_quantum::ml_dsa::MlDsa65KeyPair,
}

impl HybridKeyPair {
    /// Generate a new hybrid key pair (real Ed25519 + real ML-DSA-65).
    ///
    /// # Errors
    /// Returns an error if OS entropy is unavailable or key generation fails.
    pub fn generate() -> crate::CryptoResult<Self> {
        Ok(Self {
            classical: crate::signatures::Ed25519KeyPair::generate()?,
            pq: crate::post_quantum::ml_dsa::MlDsa65KeyPair::generate()?,
        })
    }

    /// Serialize both secret keys for custody: the Ed25519 seed followed by the
    /// ML-DSA-65 secret key. A hybrid identity is only useful if it can be
    /// persisted and recovered — otherwise it must be regenerated every restart,
    /// which loses the identity.
    ///
    /// Treat the result as secret material.
    #[must_use]
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(32 + crate::post_quantum::ml_dsa::ML_DSA_65_SK_LEN);
        out.extend_from_slice(&self.classical.seed());
        out.extend_from_slice(&self.pq.to_secret_bytes());
        out
    }

    /// Recover a hybrid key pair from [`Self::to_secret_bytes`].
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKey`](crate::CryptoError::InvalidKey) if the
    /// input is the wrong length or the ML-DSA secret key is invalid.
    pub fn from_secret_bytes(bytes: &[u8]) -> crate::CryptoResult<Self> {
        const SK: usize = crate::post_quantum::ml_dsa::ML_DSA_65_SK_LEN;
        if bytes.len() != 32 + SK {
            return Err(crate::CryptoError::InvalidKey {
                reason: format!("hybrid secret must be {} bytes, got {}", 32 + SK, bytes.len()),
            });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        let mut pq_bytes = [0u8; SK];
        pq_bytes.copy_from_slice(&bytes[32..]);
        Ok(Self {
            classical: crate::signatures::Ed25519KeyPair::from_seed(seed),
            pq: crate::post_quantum::ml_dsa::MlDsa65KeyPair::from_secret_bytes(&pq_bytes)?,
        })
    }

    /// The classical Ed25519 public key.
    #[must_use]
    pub fn classical_public_key(&self) -> crate::signatures::Ed25519PublicKey {
        self.classical.public_key()
    }

    /// The classical Ed25519 public key bytes (32).
    #[must_use]
    pub fn classical_public_key_bytes(&self) -> [u8; 32] {
        self.classical.public_key_bytes()
    }

    /// The ML-DSA-65 (Dilithium) public key.
    #[must_use]
    pub fn dilithium_public_key(&self) -> DilithiumPublicKey {
        DilithiumPublicKey(self.pq.public_key_bytes().to_vec())
    }

    /// The ML-DSA-65 public key bytes (1952).
    #[must_use]
    pub fn ml_dsa_public_key_bytes(&self) -> Vec<u8> {
        self.pq.public_key_bytes().to_vec()
    }

    /// Sign a message with both classical and post-quantum components.
    ///
    /// The result is safe against a future quantum adversary: forging it
    /// requires breaking **both** Ed25519 and ML-DSA-65, so when Ed25519 falls
    /// the ML-DSA-65 component still protects the signature.
    ///
    /// # Panics
    /// Only if ML-DSA-65 signing exhausts its internal rejection-sampling bound,
    /// which is astronomically improbable.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let classical = self.classical.sign(message);
        // ML-DSA signing is practically infallible (internal rejection loop).
        let pq_sig = self.pq.sign(message).expect("ML-DSA-65 signing");
        HybridSignature {
            classical,
            post_quantum: DilithiumSignature(pq_sig),
            level: QuantumResistanceLevel::Hybrid,
        }
    }

    /// Verify a hybrid signature against this key pair. **Both** the classical
    /// and post-quantum components must verify.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> bool {
        self.classical
            .public_key()
            .verify(message, &signature.classical)
            .is_valid()
            && crate::post_quantum::ml_dsa::verify(
                &self.pq.public_key_bytes(),
                message,
                &signature.post_quantum.0,
            )
    }
}

impl std::fmt::Debug for HybridKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridKeyPair([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_keypair_generates() {
        let kp = HybridKeyPair::generate().unwrap();
        assert_eq!(kp.classical_public_key_bytes().len(), 32);
        assert_eq!(kp.ml_dsa_public_key_bytes().len(), 1952);
    }

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let kp = HybridKeyPair::generate().unwrap();
        let sig = kp.sign(b"test message");
        assert!(sig.is_post_quantum());
        assert!(kp.verify(b"test message", &sig));
    }

    #[test]
    fn hybrid_wrong_message_fails() {
        let kp = HybridKeyPair::generate().unwrap();
        let sig = kp.sign(b"correct message");
        assert!(!kp.verify(b"wrong message", &sig));
    }

    #[test]
    fn quantum_resistance_levels() {
        assert!(!QuantumResistanceLevel::Classical.eq(&QuantumResistanceLevel::Hybrid));
        let sig = HybridSignature {
            classical: crate::signatures::Ed25519KeyPair::generate().unwrap().sign(b"msg"),
            post_quantum: DilithiumSignature(vec![]),
            level: QuantumResistanceLevel::Classical,
        };
        assert!(!sig.is_post_quantum());
    }
}
