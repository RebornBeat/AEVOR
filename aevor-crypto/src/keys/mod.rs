//! Key types, key derivation (HKDF), and key exchange (X25519).
//!
//! X25519 key exchange uses the bare `x25519_dalek::x25519()` function
//! directly with raw 32-byte scalars — no feature flags required.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Re-export key pairs from signatures module.
pub use crate::signatures::{Ed25519KeyPair, BlsKeyPair};

/// X25519 key pair for Diffie-Hellman key exchange.
///
/// Implemented using the raw `x25519_dalek::x25519()` RFC7748 function so
/// no optional feature flags are required on any version of x25519-dalek 2.x.
pub struct X25519KeyPair {
    /// Raw 32-byte secret scalar (zeroized on drop).
    secret: [u8; 32],
    /// Derived public key bytes.
    public: [u8; 32],
}

impl X25519KeyPair {
    /// Generate a new random X25519 key pair.
    ///
    /// # Errors
    /// Returns an error if the OS random number generator fails.
    pub fn generate() -> crate::CryptoResult<Self> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret)
            .map_err(|e| crate::CryptoError::KeyGenerationFailed(e.to_string()))?;

        // Clamp the scalar per RFC7748 §5.
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;

        // Public key = scalar * basepoint
        let public = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        Ok(Self { secret, public })
    }

    /// Get the public key bytes.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    /// Perform ECDH with a remote public key, returning the 32-byte shared secret.
    ///
    /// # Errors
    /// This function currently always succeeds; the `Result` type allows future
    /// validation of the remote public key (e.g. rejecting low-order points).
    pub fn diffie_hellman(&self, remote_public: &[u8; 32]) -> crate::CryptoResult<[u8; 32]> {
        Ok(x25519_dalek::x25519(self.secret, *remote_public))
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Clone for X25519KeyPair {
    fn clone(&self) -> Self {
        Self { secret: self.secret, public: self.public }
    }
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519KeyPair(public={})", hex::encode(&self.public[..8]))
    }
}

/// A derived key produced by HKDF.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey {
    /// The raw derived key bytes (32 bytes).
    pub key_bytes: [u8; 32],
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DerivedKey([REDACTED])")
    }
}

/// A BIP-32-inspired hierarchical key derivation path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDerivationPath {
    /// Path component indices.
    pub components: Vec<u32>,
    /// Whether each component is hardened.
    pub hardened: Vec<bool>,
}

impl KeyDerivationPath {
    /// Create a new derivation path.
    pub fn new(components: Vec<u32>, hardened: Vec<bool>) -> Self {
        Self { components, hardened }
    }

    /// Standard path for validator signing keys.
    pub fn validator_key() -> Self {
        Self::new(vec![44, 424, 0, 0], vec![true, true, true, false])
    }

    /// Standard path for TEE service keys.
    pub fn tee_key() -> Self {
        Self::new(vec![44, 424, 1, 0], vec![true, true, true, false])
    }
}

/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) using SHA-256.
pub struct Hkdf;

impl Hkdf {
    /// Extract and expand `out_len` bytes from input key material.
    ///
    /// # Errors
    /// Returns an error if `out_len` exceeds the HKDF maximum output length (255 × `hash_len`).
    pub fn derive(
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        out_len: usize,
    ) -> crate::CryptoResult<Vec<u8>> {
        use hkdf::Hkdf as HkdfImpl;
        use sha2::Sha256;

        let hk = HkdfImpl::<Sha256>::new(salt, ikm);
        let mut output = vec![0u8; out_len];
        hk.expand(info, &mut output)
            .map_err(|_| crate::CryptoError::KeyGenerationFailed(
                "HKDF expand failed: output length too long".into()
            ))?;
        Ok(output)
    }

    /// Derive a 32-byte key for a specific domain label.
    ///
    /// # Errors
    /// Returns an error if the underlying HKDF expand step fails (extremely rare).
    pub fn derive_key(master: &[u8], domain: &str) -> crate::CryptoResult<[u8; 32]> {
        let derived = Self::derive(master, None, domain.as_bytes(), 32)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_ecdh_agreement() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        let alice_shared = alice.diffie_hellman(&bob.public_bytes()).unwrap();
        let bob_shared = bob.diffie_hellman(&alice.public_bytes()).unwrap();
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn x25519_different_peers_different_secrets() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        let carol = X25519KeyPair::generate().unwrap();
        let alice_bob = alice.diffie_hellman(&bob.public_bytes()).unwrap();
        let alice_carol = alice.diffie_hellman(&carol.public_bytes()).unwrap();
        assert_ne!(alice_bob, alice_carol);
    }

    #[test]
    fn x25519_reusable_multiple_exchanges() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        // Same key can be reused for multiple exchanges (deterministic)
        let s1 = alice.diffie_hellman(&bob.public_bytes()).unwrap();
        let s2 = alice.diffie_hellman(&bob.public_bytes()).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn x25519_public_key_from_basepoint() {
        // Known basepoint test: generating from any secret produces non-zero pubkey
        let kp = X25519KeyPair::generate().unwrap();
        assert_ne!(kp.public_bytes(), [0u8; 32]);
    }

    #[test]
    fn hkdf_derive_key_is_deterministic() {
        let master = b"master key material for testing";
        let k1 = Hkdf::derive_key(master, "test-domain").unwrap();
        let k2 = Hkdf::derive_key(master, "test-domain").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn hkdf_different_domains_produce_different_keys() {
        let master = b"master key material for testing";
        let k1 = Hkdf::derive_key(master, "domain-a").unwrap();
        let k2 = Hkdf::derive_key(master, "domain-b").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn hkdf_different_masters_produce_different_keys() {
        let k1 = Hkdf::derive_key(b"master-1", "domain").unwrap();
        let k2 = Hkdf::derive_key(b"master-2", "domain").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn validator_key_path_is_hardened() {
        let path = KeyDerivationPath::validator_key();
        assert!(path.hardened[0]);
        assert!(path.hardened[1]);
        assert!(path.hardened[2]);
    }

    #[test]
    fn rfc7748_known_vector() {
        // RFC 7748 §6.1 test vector
        let alice_private = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let alice_public_expected = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let alice_public = x25519_dalek::x25519(alice_private, x25519_dalek::X25519_BASEPOINT_BYTES);
        assert_eq!(alice_public, alice_public_expected);
    }
}
