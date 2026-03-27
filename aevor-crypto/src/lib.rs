//! # AEVOR Crypto: Performance-Optimized Cryptographic Primitives
//!
//! `aevor-crypto` provides all cryptographic operations for AEVOR with a strict
//! performance-first design. Every algorithm choice is justified by the needs of
//! the revolutionary architecture — no academic formalism, no computationally
//! expensive techniques that would compromise the 200,000+ TPS throughput target.
//!
//! ## Algorithm Selection Rationale
//!
//! - **BLAKE3**: Primary hash function — faster than SHA-256, parallel-friendly.
//! - **SHA-256/SHA-512**: Compatibility hashes for external integration and DNSSEC.
//! - **Ed25519**: Transaction signing — constant-time, high throughput.
//! - **BLS12-381**: Consensus aggregation — O(1) aggregate verification.
//! - **ChaCha20-Poly1305**: Authenticated encryption — constant-time, no timing leakage.
//! - **X25519**: Key exchange — efficient, well-analyzed.
//!
//! ## What This Crate Explicitly Excludes
//!
//! **Homomorphic encryption** (Paillier, `ElGamal`, BFV, CKKS) is intentionally absent.
//! These schemes create 1,000×–1,000,000× computational overhead that would destroy
//! throughput goals. Privacy is achieved through TEE hardware isolation (1.1×–1.3×
//! overhead) providing stronger guarantees without the performance penalty.
//!
//! **Formal mathematical proof systems** for basic operations are excluded. Mathematical
//! certainty is achieved through architectural design and TEE attestation, not
//! computational proof overhead that forces sequential verification.
//!
//! ## Hardware Acceleration
//!
//! The `acceleration` module provides architecture-specific optimizations for `x86_64`
//! (AES-NI, AVX2, SHA Extensions), `AArch64` (NEON, ARM Crypto Extensions), and
//! RISC-V (Vector Extensions) while maintaining identical results across all platforms.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Hash functions: BLAKE3 (primary), SHA-256, SHA-512, Keccak-256 (bridge compatibility).
pub mod hash;

/// Digital signature schemes: Ed25519 (transactions), BLS12-381 (consensus aggregation).
pub mod signatures;

/// Zero-knowledge proofs: Groth16, PLONK, Bulletproofs, STARK — type definitions and
/// verification interfaces. Proof generation belongs in `aevor-zk`.
pub mod proofs;

/// Symmetric encryption: ChaCha20-Poly1305, AES-256-GCM for TEE-coordinated data protection.
pub mod encryption;

/// Key types and key derivation: Ed25519 keys, BLS keys, X25519 key exchange, HKDF.
pub mod keys;

/// Hardware acceleration: architecture-specific optimizations with cross-platform fallbacks.
pub mod acceleration;

/// Cryptographic primitives re-exported from `aevor-core::crypto` with implementations.
pub mod primitives;

/// Commitment schemes: Pedersen, KZG, hash-based, Poseidon.
pub mod commitment;

/// BLS12-381 signature aggregation for consensus signature collection.
pub mod bls;

/// Merkle tree construction and proof generation.
pub mod merkle;

/// Post-quantum hybrid schemes: current algorithms + CRYSTALS-Dilithium for future-proofing.
pub mod post_quantum;

// ============================================================
// PRELUDE
// ============================================================

/// Crypto prelude — all essential cryptographic types.
///
/// ```rust
/// use aevor_crypto::prelude::*;
/// ```
pub mod prelude {
    pub use crate::hash::{
        Blake3Hash, Blake3Hasher, Sha256Hash, Sha256Hasher, Sha512Hash,
        Keccak256Hash, ConsensusHash, PrivacyHash, HashAlgorithm,
    };
    pub use crate::signatures::{
        Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature,
        BlsKeyPair, BlsPublicKey, BlsSignature,
        SignatureAlgorithm, SignatureVerification,
    };
    pub use crate::proofs::{
        GrothProof, PlonkProof, BulletProof, StarkProof, Halo2Proof,
        ProofSystem, ProofVerifier, ProvingKey, VerifyingKey,
    };
    pub use crate::encryption::{
        ChaCha20Poly1305Cipher, AesGcmCipher, EncryptedData,
        EncryptionKey, DecryptionKey, Nonce as EncryptionNonce, AuthTag,
    };
    pub use crate::keys::{
        Ed25519KeyPair as SigningKeyPair, BlsKeyPair as ConsensusKeyPair,
        X25519KeyPair, DerivedKey, KeyDerivationPath, Hkdf,
    };
    pub use crate::commitment::{
        PedersenCommitment, KzgCommitment, HashCommitment, PoseidonCommitment,
        CommitmentOpening, CommitmentScheme,
    };
    pub use crate::bls::{
        BlsAggregateSignature, BlsAggregator, BlsBatchVerifier,
        ParticipantBitmap,
    };
    pub use crate::merkle::{
        MerkleTree, MerkleProof, MerkleRoot, SparseMerkleTree,
        IncrementalMerkleTree,
    };
    pub use crate::post_quantum::{
        HybridKeyPair, DilithiumPublicKey, DilithiumSignature,
        HybridSignature, QuantumResistanceLevel,
    };
    pub use crate::{CryptoError, CryptoResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from cryptographic operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum CryptoError {
    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid key material provided.
    #[error("invalid key: {reason}")]
    InvalidKey {
        /// Description of why the key is invalid.
        reason: String,
    },

    /// Proof verification failed.
    #[error("proof verification failed: {system}")]
    ProofVerificationFailed {
        /// Name of the proof system that rejected the proof.
        system: String,
    },

    /// Encryption or decryption failure.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// Hash computation error (extremely rare — indicates platform issue).
    #[error("hash computation error: {0}")]
    HashError(String),

    /// Requested hardware acceleration is unavailable.
    #[error("hardware acceleration unavailable: {feature}")]
    AccelerationUnavailable {
        /// The acceleration feature that was not found.
        feature: String,
    },

    /// Commitment scheme error.
    #[error("commitment error: {0}")]
    CommitmentError(String),

    /// BLS aggregation error.
    #[error("BLS aggregation error: {0}")]
    BlsAggregationError(String),

    /// Random number generation failure.
    #[error("RNG failure: {0}")]
    RngFailure(String),

    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),
}

/// Convenience alias for cryptographic results.
pub type CryptoResult<T> = Result<T, CryptoError>;

// ============================================================
// CONSTANTS
// ============================================================

/// BLAKE3 output size in bytes.
pub const BLAKE3_OUTPUT_SIZE: usize = 32;

/// SHA-256 output size in bytes.
pub const SHA256_OUTPUT_SIZE: usize = 32;

/// SHA-512 output size in bytes.
pub const SHA512_OUTPUT_SIZE: usize = 64;

/// Keccak-256 output size in bytes.
pub const KECCAK256_OUTPUT_SIZE: usize = 32;

/// Ed25519 public key size in bytes.
pub const ED25519_PUBKEY_BYTES: usize = 32;

/// Ed25519 signature size in bytes.
pub const ED25519_SIG_BYTES: usize = 64;

/// BLS12-381 public key size in bytes (G1 compressed).
pub const BLS_PUBKEY_BYTES: usize = 48;

/// BLS12-381 signature size in bytes (G2 compressed).
pub const BLS_SIG_BYTES: usize = 96;

/// ChaCha20-Poly1305 nonce size in bytes.
pub const CHACHA20_NONCE_BYTES: usize = 12;

/// ChaCha20-Poly1305 authentication tag size in bytes.
pub const CHACHA20_TAG_BYTES: usize = 16;

/// AES-256-GCM key size in bytes.
pub const AES_256_KEY_BYTES: usize = 32;

/// AES-256-GCM nonce size in bytes.
pub const AES_256_NONCE_BYTES: usize = 12;

/// X25519 key size in bytes.
pub const X25519_KEY_BYTES: usize = 32;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_output_sizes_are_correct() {
        assert_eq!(BLAKE3_OUTPUT_SIZE, 32);
        assert_eq!(SHA256_OUTPUT_SIZE, 32);
        assert_eq!(SHA512_OUTPUT_SIZE, 64);
        assert_eq!(KECCAK256_OUTPUT_SIZE, 32);
    }

    #[test]
    fn key_sizes_are_correct() {
        assert_eq!(ED25519_PUBKEY_BYTES, 32);
        assert_eq!(ED25519_SIG_BYTES, 64);
        assert_eq!(BLS_PUBKEY_BYTES, 48);
        assert_eq!(BLS_SIG_BYTES, 96);
    }

    #[test]
    fn encryption_constants_are_correct() {
        assert_eq!(CHACHA20_NONCE_BYTES, 12);
        assert_eq!(CHACHA20_TAG_BYTES, 16);
        assert_eq!(AES_256_KEY_BYTES, 32);
        assert_eq!(AES_256_NONCE_BYTES, 12);
    }

    #[test]
    fn x25519_key_size_matches_constant() {
        assert_eq!(X25519_KEY_BYTES, 32);
    }

    #[test]
    fn crypto_error_display_is_informative() {
        let e = CryptoError::InvalidKey { reason: "too short".into() };
        assert!(e.to_string().contains("too short"));

        let e2 = CryptoError::EncryptionError("bad nonce".into());
        assert!(e2.to_string().contains("bad nonce"));

        let e3 = CryptoError::ProofVerificationFailed { system: "Groth16".into() };
        assert!(e3.to_string().contains("Groth16"));
    }

    #[test]
    fn crypto_result_ok_and_err() {
        let ok: CryptoResult<u64> = Ok(99);
        assert!(ok.is_ok());
        let err: CryptoResult<u64> = Err(CryptoError::SignatureVerificationFailed);
        assert!(err.is_err());
    }
}
