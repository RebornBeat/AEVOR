//! Light client: header-only verification without a full node.
//!
//! A light client downloads only block headers and uses Merkle proofs
//! to verify specific state entries without storing the full blockchain.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_core::storage::MerkleProof;
use crate::ClientResult;

/// Configuration for a light client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightClientConfig {
    /// A trusted checkpoint header hash to bootstrap from.
    ///
    /// If `None`, the client will attempt to sync from genesis (slow).
    /// In practice always set this to a recent finalized block hash.
    pub trusted_checkpoint: Option<Hash256>,
    /// Maximum number of headers to download per sync batch.
    pub max_headers_to_sync: u64,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self { trusted_checkpoint: None, max_headers_to_sync: 10_000 }
    }
}

/// Tracks the light client's current sync position.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderSyncState {
    /// The highest block height whose header the client has verified.
    pub synced_to_height: u64,
    /// The state root of the last verified header.
    pub trusted_root: Hash256,
}

impl HeaderSyncState {
    /// Initial state before any headers have been synced.
    pub fn genesis() -> Self {
        Self { synced_to_height: 0, trusted_root: Hash256::ZERO }
    }
    /// Returns `true` if the client has synced at least one header.
    pub fn is_synced(&self) -> bool { self.synced_to_height > 0 }
}

/// A response whose correctness has been verified with a Merkle proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleVerifiedResponse {
    /// The response data (e.g. serialized object state).
    pub data: Vec<u8>,
    /// The Merkle proof linking this data to the trusted state root.
    pub proof: MerkleProof,
    /// Whether the proof verification passed.
    pub verified: bool,
}

impl MerkleVerifiedResponse {
    /// Returns `true` if the data is cryptographically verified.
    pub fn is_verified(&self) -> bool { self.verified }
}

/// A proof that links a block header to a trusted checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightClientProof {
    /// Hash of the block header this proof covers.
    pub header_hash: Hash256,
    /// Merkle proof linking this header to the checkpoint root.
    pub merkle_proof: MerkleProof,
}

impl LightClientProof {
    /// Verify this proof against a trusted root hash.
    pub fn verify(&self, trusted_root: &Hash256) -> bool {
        self.merkle_proof.verify_against(trusted_root, &self.header_hash.0)
    }
}

/// Light client: syncs block headers and verifies state proofs.
pub struct LightClient {
    config: LightClientConfig,
    state: HeaderSyncState,
}

impl LightClient {
    /// Create a light client with the given configuration.
    ///
    /// If `config.trusted_checkpoint` is set, the client starts from that
    /// checkpoint rather than syncing from genesis.
    pub fn new(config: LightClientConfig) -> Self {
        let trusted_root = config.trusted_checkpoint.unwrap_or(Hash256::ZERO);
        let state = HeaderSyncState { synced_to_height: 0, trusted_root };
        Self { config, state }
    }

    /// The block height this client has synced up to.
    pub fn sync_height(&self) -> u64 { self.state.synced_to_height }

    /// The current trusted state root.
    pub fn trusted_root(&self) -> Hash256 { self.state.trusted_root }

    /// The configuration for this light client.
    pub fn config(&self) -> &LightClientConfig { &self.config }

    /// Returns `true` if the client has synced at least one header.
    pub fn is_synced(&self) -> bool { self.state.is_synced() }

    /// Verify a Merkle proof against the client's current trusted root.
    pub fn verify_proof(&self, proof: &LightClientProof) -> bool {
        proof.verify(&self.state.trusted_root)
    }

    /// Advance the trusted root after verifying a new header.
    ///
    /// In a full implementation this would validate the header's signature
    /// against the validator set before accepting it.
    ///
    /// # Errors
    /// Returns an error if `new_height` is not strictly greater than the current synced height.
    pub fn advance(&mut self, new_height: u64, new_root: Hash256) -> ClientResult<()> {
        if new_height <= self.state.synced_to_height {
            return Err(crate::ClientError::InvalidResponse {
                reason: format!(
                    "height {new_height} is not newer than synced height {}",
                    self.state.synced_to_height
                ),
            });
        }
        self.state.synced_to_height = new_height;
        self.state.trusted_root = new_root;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn hash(n: u8) -> Hash256 { Hash256([n; 32]) }

    #[test]
    fn light_client_config_default_no_checkpoint() {
        let cfg = LightClientConfig::default();
        assert!(cfg.trusted_checkpoint.is_none());
        assert_eq!(cfg.max_headers_to_sync, 10_000);
    }

    #[test]
    fn header_sync_state_genesis_is_not_synced() {
        let state = HeaderSyncState::genesis();
        assert_eq!(state.synced_to_height, 0);
        assert!(!state.is_synced());
        assert_eq!(state.trusted_root, Hash256::ZERO);
    }

    #[test]
    fn light_client_starts_unsynced() {
        let client = LightClient::new(LightClientConfig::default());
        assert!(!client.is_synced());
        assert_eq!(client.sync_height(), 0);
        assert_eq!(client.trusted_root(), Hash256::ZERO);
    }

    #[test]
    fn light_client_with_checkpoint_uses_it_as_root() {
        let cfg = LightClientConfig {
            trusted_checkpoint: Some(hash(7)),
            max_headers_to_sync: 1000,
        };
        let client = LightClient::new(cfg);
        assert_eq!(client.trusted_root(), hash(7));
    }

    #[test]
    fn light_client_advance_updates_height_and_root() {
        let mut client = LightClient::new(LightClientConfig::default());
        client.advance(100, hash(5)).unwrap();
        assert_eq!(client.sync_height(), 100);
        assert_eq!(client.trusted_root(), hash(5));
        assert!(client.is_synced());
    }

    #[test]
    fn light_client_advance_rejects_non_increasing_height() {
        let mut client = LightClient::new(LightClientConfig::default());
        client.advance(100, hash(1)).unwrap();
        assert!(client.advance(100, hash(2)).is_err()); // same height
        assert!(client.advance(50, hash(3)).is_err());  // lower height
        assert_eq!(client.sync_height(), 100); // unchanged
    }

    #[test]
    fn merkle_verified_response_is_verified_flag() {
        let proof = aevor_core::storage::MerkleProof {
            key: aevor_core::storage::StorageKey(vec![1]),
            value: aevor_core::storage::StorageValue(vec![]),
            siblings: vec![],
            root: aevor_core::storage::MerkleRoot::EMPTY,
            is_inclusion: false,
        };
        let resp = MerkleVerifiedResponse { data: vec![42], proof, verified: true };
        assert!(resp.is_verified());
    }
}
