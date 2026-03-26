//! Post-quantum hybrid schemes: Ed25519 + CRYSTALS-Dilithium.
//!
//! Classical algorithms remain primary for performance; PQ algorithms
//! provide cryptographic agility for future-proofing.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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

/// Hybrid key pair: Ed25519 + Dilithium.
///
/// The Dilithium component uses a stub implementation — the full
/// `pqcrypto-dilithium` crate integration is a drop-in replacement.
pub struct HybridKeyPair {
    classical: crate::signatures::Ed25519KeyPair,
    pq_secret: Vec<u8>,
    pq_public: Vec<u8>,
}

impl HybridKeyPair {
    /// Generate a new hybrid key pair.
    pub fn generate() -> crate::CryptoResult<Self> {
        let classical = crate::signatures::Ed25519KeyPair::generate()?;

        // Dilithium stub: derive a deterministic PQ key from random seed.
        // Full implementation uses pqcrypto-dilithium::dilithium3::keypair().
        let mut pq_seed = [0u8; 32];
        getrandom::getrandom(&mut pq_seed)
            .map_err(|e| crate::CryptoError::KeyGenerationFailed(e.to_string()))?;

        // Public key = BLAKE3(seed || "dilithium-pk")
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pq_seed);
        hasher.update(b"dilithium-pk");
        let pq_public = hasher.finalize().as_bytes().to_vec();

        Ok(Self {
            classical,
            pq_secret: pq_seed.to_vec(),
            pq_public,
        })
    }

    /// The classical Ed25519 public key.
    pub fn classical_public_key(&self) -> crate::signatures::Ed25519PublicKey {
        self.classical.public_key()
    }

    /// The Dilithium public key.
    pub fn dilithium_public_key(&self) -> DilithiumPublicKey {
        DilithiumPublicKey(self.pq_public.clone())
    }

    /// Sign a message with both classical and post-quantum components.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let classical = self.classical.sign(message);

        // Dilithium stub: signature = BLAKE3(secret || message)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.pq_secret);
        hasher.update(message);
        let pq_sig = DilithiumSignature(hasher.finalize().as_bytes().to_vec());

        HybridSignature {
            classical,
            post_quantum: pq_sig,
            level: QuantumResistanceLevel::Hybrid,
        }
    }

    /// Verify a hybrid signature.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> bool {
        // Classical component must verify.
        if !self.classical.public_key().verify(message, &signature.classical).is_valid() {
            return false;
        }
        // PQ component: verify stub (BLAKE3 check).
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.pq_secret);
        hasher.update(message);
        let expected = hasher.finalize().as_bytes().to_vec();
        signature.post_quantum.0 == expected
    }
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        self.pq_secret.zeroize();
    }
}

impl Clone for HybridKeyPair {
    fn clone(&self) -> Self {
        Self {
            classical: self.classical.clone(),
            pq_secret: self.pq_secret.clone(),
            pq_public: self.pq_public.clone(),
        }
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
        assert!(!kp.pq_public.is_empty());
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
