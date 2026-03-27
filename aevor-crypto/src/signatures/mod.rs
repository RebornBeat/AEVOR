//! Ed25519 and BLS12-381 signature schemes.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Signature;
use zeroize::Zeroize;

/// Signature algorithm identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Ed25519 — transaction signing.
    Ed25519,
    /// BLS12-381 — consensus aggregation.
    Bls12_381,
    /// Hybrid Ed25519 + Dilithium — post-quantum.
    HybridEd25519Dilithium,
}

/// Result of signature verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureVerification {
    /// Signature is valid.
    Valid,
    /// Signature is invalid.
    Invalid,
}

impl SignatureVerification {
    /// Returns `true` if the signature is valid.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

// ============================================================
// ED25519
// ============================================================

/// Ed25519 key pair (signing key + verification key).
pub struct Ed25519KeyPair {
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a new random key pair.
    ///
    /// # Errors
    /// Returns an error if the OS random number generator fails.
    pub fn generate() -> crate::CryptoResult<Self> {
        use rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        Ok(Self { signing_key })
    }

    /// Create from a 32-byte secret seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        Self { signing_key }
    }

    /// The public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.signing_key.verifying_key().to_bytes())
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(message);
        Ed25519Signature(Signature(sig.to_bytes()))
    }

    /// Return the raw 32-byte public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Verify a signature given raw public key bytes (no key pair needed).
    pub fn verify_raw(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        vk.verify(message, &sig).is_ok()
    }
}

impl Clone for Ed25519KeyPair {
    fn clone(&self) -> Self {
        Self { signing_key: ed25519_dalek::SigningKey::from_bytes(&self.signing_key.to_bytes()) }
    }
}

impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519KeyPair({}...)", hex::encode(&self.signing_key.verifying_key().to_bytes()[..8]))
    }
}

/// Ed25519 public key (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Ed25519PublicKey {
    /// Verify a signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> SignatureVerification {
        use ed25519_dalek::Verifier;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.0) else {
            return SignatureVerification::Invalid;
        };
        // ed25519-dalek 2.x: from_bytes returns Signature directly (not Result)
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0.0);
        if vk.verify(message, &sig).is_ok() {
            SignatureVerification::Valid
        } else {
            SignatureVerification::Invalid
        }
    }

    /// Derive an AEVOR address from this public key.
    pub fn to_address(&self) -> aevor_core::primitives::Address {
        aevor_core::primitives::PublicKey(self.0).to_address()
    }
}

/// Ed25519 signature (64 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Signature(pub Signature);

// ============================================================
// BLS12-381
// ============================================================

/// BLS12-381 key pair for consensus aggregation.
pub struct BlsKeyPair {
    secret_bytes: Vec<u8>,
    public_bytes: Vec<u8>,
}

impl BlsKeyPair {
    /// Generate a new random BLS key pair.
    ///
    /// # Errors
    /// Returns an error if OS entropy is unavailable or BLS key generation fails.
    pub fn generate() -> crate::CryptoResult<Self> {
        let mut ikm = [0u8; 32];
        getrandom::getrandom(&mut ikm)
            .map_err(|e| crate::CryptoError::KeyGenerationFailed(e.to_string()))?;

        let sk = blst::min_sig::SecretKey::key_gen(&ikm, &[])
            .map_err(|e| crate::CryptoError::KeyGenerationFailed(format!("{e:?}")))?;
        let pk = sk.sk_to_pk();

        Ok(Self {
            secret_bytes: sk.to_bytes().to_vec(),
            public_bytes: pk.compress().to_vec(),
        })
    }

    /// The public key.
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.public_bytes.clone())
    }

    /// Sign a message.
    ///
    /// # Panics
    /// Does not panic in practice — secret bytes were produced by `generate()` and are
    /// always a valid BLS secret key. The `expect` is a safety assertion only.
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let sk = blst::min_sig::SecretKey::from_bytes(&self.secret_bytes)
            .expect("valid BLS secret key");
        let sig = sk.sign(message, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_", &[]);
        BlsSignature(sig.compress().to_vec())
    }
}

impl Drop for BlsKeyPair {
    fn drop(&mut self) {
        self.secret_bytes.zeroize();
    }
}

impl std::fmt::Debug for BlsKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlsKeyPair([{}b public])", self.public_bytes.len())
    }
}

impl Clone for BlsKeyPair {
    fn clone(&self) -> Self {
        Self {
            secret_bytes: self.secret_bytes.clone(),
            public_bytes: self.public_bytes.clone(),
        }
    }
}

/// BLS12-381 public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlsPublicKey(pub Vec<u8>);

impl BlsPublicKey {
    /// Verify a BLS signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> SignatureVerification {
        let Ok(pk) = blst::min_sig::PublicKey::uncompress(&self.0) else {
            return SignatureVerification::Invalid;
        };
        let Ok(sig) = blst::min_sig::Signature::uncompress(&signature.0) else {
            return SignatureVerification::Invalid;
        };
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let err = sig.verify(true, message, dst, &[], &pk, true);
        if matches!(err, blst::BLST_ERROR::BLST_SUCCESS) {
            SignatureVerification::Valid
        } else {
            SignatureVerification::Invalid
        }
    }
}

/// BLS12-381 signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsSignature(pub Vec<u8>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let msg = b"test message for signing";
        let sig = kp.sign(msg);
        assert!(kp.public_key().verify(msg, &sig).is_valid());
    }

    #[test]
    fn ed25519_wrong_message_fails() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let sig = kp.sign(b"correct message");
        assert!(!kp.public_key().verify(b"wrong message", &sig).is_valid());
    }

    #[test]
    fn bls_sign_verify_roundtrip() {
        let kp = BlsKeyPair::generate().unwrap();
        let msg = b"bls test message";
        let sig = kp.sign(msg);
        assert!(kp.public_key().verify(msg, &sig).is_valid());
    }

    #[test]
    fn bls_wrong_message_fails() {
        let kp = BlsKeyPair::generate().unwrap();
        let sig = kp.sign(b"correct");
        assert!(!kp.public_key().verify(b"wrong", &sig).is_valid());
    }
}
