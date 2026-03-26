//! Hash functions: BLAKE3 (primary), SHA-256, SHA-512, Keccak-256 (EVM bridge compat).

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Hash256, Hash512};

/// Algorithm identifier for hash function selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// BLAKE3 — primary hash function, faster than SHA-256.
    Blake3,
    /// SHA-256 — standard hash for external compatibility.
    Sha256,
    /// SHA-512 — wide-output hash for extra security margin.
    Sha512,
    /// Keccak-256 — Ethereum/EVM compatibility.
    Keccak256,
}

impl HashAlgorithm {
    /// Output size in bytes for this algorithm.
    pub fn output_size_bytes(&self) -> usize {
        match self {
            Self::Blake3 | Self::Sha256 | Self::Keccak256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// BLAKE3 hash output (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Blake3Hash(pub Hash256);

impl Blake3Hash {
    /// Hash `data` with BLAKE3.
    pub fn hash(data: &[u8]) -> Self {
        Self(Hash256(*blake3::hash(data).as_bytes()))
    }
    /// View the inner `Hash256`.
    pub fn as_hash(&self) -> &Hash256 { &self.0 }
}

/// BLAKE3 incremental hasher — feed data in chunks, finalize once.
pub struct Blake3Hasher(blake3::Hasher);

impl Blake3Hasher {
    /// Create a new BLAKE3 hasher.
    pub fn new() -> Self { Self(blake3::Hasher::new()) }
    /// Feed more data into the hasher.
    pub fn update(&mut self, data: &[u8]) { self.0.update(data); }
    /// Finalize and return the hash.
    pub fn finalize(&self) -> Blake3Hash {
        Blake3Hash(Hash256(*self.0.finalize().as_bytes()))
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self { Self::new() }
}

/// SHA-256 hash output (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256Hash(pub Hash256);

impl Sha256Hash {
    /// Hash `data` with SHA-256.
    pub fn hash(data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        h.update(data);
        let result = h.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(Hash256(bytes))
    }
}

/// SHA-256 incremental hasher.
pub struct Sha256Hasher(sha2::Sha256);

impl Sha256Hasher {
    /// Create a new SHA-256 hasher.
    pub fn new() -> Self {
        use sha2::Digest;
        Self(sha2::Sha256::new())
    }
    /// Feed more data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.0.update(data);
    }
    /// Finalize and return the hash.
    pub fn finalize(self) -> Sha256Hash {
        use sha2::Digest;
        let result = self.0.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Sha256Hash(Hash256(bytes))
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self { Self::new() }
}

/// SHA-512 hash output (64 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha512Hash(pub Hash512);

impl Sha512Hash {
    /// Hash `data` with SHA-512.
    pub fn hash(data: &[u8]) -> Self {
        use sha2::{Sha512, Digest};
        let mut h = Sha512::new();
        h.update(data);
        let result = h.finalize();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&result);
        Self(Hash512(bytes))
    }
}

/// Keccak-256 hash (for EVM / bridge compatibility).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Keccak256Hash(pub Hash256);

impl Keccak256Hash {
    /// Hash `data` with Keccak-256 (Ethereum-compatible).
    pub fn hash(data: &[u8]) -> Self {
        use sha3::{Keccak256, Digest};
        let mut h = Keccak256::new();
        h.update(data);
        let result = h.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(Hash256(bytes))
    }
}

/// Domain-separated BLAKE3 hash for consensus operations.
///
/// Prevents cross-context hash collisions by prepending a domain tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusHash(pub Hash256);

impl ConsensusHash {
    /// Hash `data` with the consensus domain separator.
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"aevor-consensus-v1:");
        hasher.update(data);
        Self(hasher.finalize().0)
    }
}

/// Domain-separated BLAKE3 hash for privacy operations.
///
/// Prevents cross-context hash collisions by prepending a domain tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrivacyHash(pub Hash256);

impl PrivacyHash {
    /// Hash `data` with the privacy domain separator.
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"aevor-privacy-v1:");
        hasher.update(data);
        Self(hasher.finalize().0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_is_deterministic() {
        let h1 = Blake3Hash::hash(b"hello");
        let h2 = Blake3Hash::hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_different_hashes() {
        let h1 = Blake3Hash::hash(b"hello");
        let h2 = Blake3Hash::hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn domain_separation_produces_different_hashes() {
        let data = b"same data";
        let c = ConsensusHash::hash(data);
        let p = PrivacyHash::hash(data);
        assert_ne!(c.0, p.0);
    }

    #[test]
    fn sha256_output_size() {
        assert_eq!(HashAlgorithm::Sha256.output_size_bytes(), 32);
    }

    #[test]
    fn sha512_output_size() {
        assert_eq!(HashAlgorithm::Sha512.output_size_bytes(), 64);
    }

    #[test]
    fn keccak256_is_deterministic() {
        let h1 = Keccak256Hash::hash(b"data");
        let h2 = Keccak256Hash::hash(b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_incremental_matches_oneshot() {
        let data = b"incremental test data";
        let oneshot = Blake3Hash::hash(data);
        let mut hasher = Blake3Hasher::new();
        hasher.update(&data[..5]);
        hasher.update(&data[5..]);
        let incremental = hasher.finalize();
        assert_eq!(oneshot, incremental);
    }
}
