//! Canonical BLAKE3 hashing.
//!
//! This is the single home for the project's primary hash primitive. It lives in
//! `aevor-core` (the base crate every other crate depends on) so there is one
//! definition, reachable everywhere. `aevor-crypto` re-exports [`Blake3Hasher`]
//! and [`Blake3Hash`] from here, so existing `aevor_crypto::hash::…` imports keep
//! working while pointing at this one implementation.

use serde::{Deserialize, Serialize};

use crate::primitives::Hash256;

/// BLAKE3 hash output (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Blake3Hash(pub Hash256);

impl Blake3Hash {
    /// Hash `data` with BLAKE3.
    #[must_use]
    pub fn hash(data: &[u8]) -> Self {
        Self(Hash256(*blake3::hash(data).as_bytes()))
    }

    /// View the inner [`Hash256`].
    #[must_use]
    pub fn as_hash(&self) -> &Hash256 {
        &self.0
    }
}

/// BLAKE3 incremental hasher — feed data in chunks, finalize once.
pub struct Blake3Hasher(blake3::Hasher);

impl Blake3Hasher {
    /// Create a new BLAKE3 hasher.
    #[must_use]
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }

    /// Feed more data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finalize and return the hash.
    #[must_use]
    pub fn finalize(&self) -> Blake3Hash {
        Blake3Hash(Hash256(*self.0.finalize().as_bytes()))
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}
