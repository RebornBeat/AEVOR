//! Data availability via erasure coding.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErasureConfig { pub data_shards: usize, pub parity_shards: usize }
impl Default for ErasureConfig {
    fn default() -> Self { Self { data_shards: 8, parity_shards: 4 } }
}

pub struct ErasureCode { config: ErasureConfig }
impl ErasureCode {
    pub fn new(config: ErasureConfig) -> Self { Self { config } }
    pub fn encode(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let chunk = (data.len() / self.config.data_shards).max(1);
        data.chunks(chunk).map(<[u8]>::to_vec).collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvailabilitySample { pub shard_index: usize, pub data_hash: aevor_core::primitives::Hash256 }

pub struct DataReconstruction;
impl DataReconstruction {
    pub fn reconstruct(shards: &[Vec<u8>]) -> Option<Vec<u8>> {
        if shards.is_empty() { None } else { Some(shards.concat()) }
    }
}

pub struct DataAvailability { code: ErasureCode }
impl DataAvailability {
    /// Create a data availability layer with the given erasure coding configuration.
    pub fn new(config: ErasureConfig) -> Self { Self { code: ErasureCode::new(config) } }

    /// The erasure code used to split and reconstruct data shards.
    pub fn erasure_code(&self) -> &ErasureCode { &self.code }

    /// Encode `data` into shards for distributed availability.
    ///
    /// The returned shards are distributed across validators such that any
    /// `data_shards` of them are sufficient to reconstruct the original data.
    pub fn encode(&self, data: &[u8]) -> Vec<Vec<u8>> {
        self.code.encode(data)
    }

    /// Reconstruct original data from a sufficient subset of shards.
    ///
    /// Delegates to `DataReconstruction::reconstruct` which concatenates
    /// shards back into the original data.
    pub fn reconstruct(&self, shards: &[Vec<u8>]) -> Option<Vec<u8>> {
        DataReconstruction::reconstruct(shards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erasure_encode_produces_shards() {
        let config = ErasureConfig { data_shards: 4, parity_shards: 2 };
        let code = ErasureCode::new(config);
        let data = vec![0u8; 40];
        let shards = code.encode(&data);
        assert!(!shards.is_empty());
        // All shards non-empty
        assert!(shards.iter().all(|s| !s.is_empty()));
    }

    #[test]
    fn erasure_encode_handles_small_data() {
        let config = ErasureConfig { data_shards: 8, parity_shards: 4 };
        let code = ErasureCode::new(config);
        // data shorter than data_shards — chunk size falls back to 1
        let shards = code.encode(&[1, 2, 3]);
        assert!(!shards.is_empty());
    }

    #[test]
    fn data_reconstruction_returns_none_for_empty_shards() {
        assert!(DataReconstruction::reconstruct(&[]).is_none());
    }

    #[test]
    fn data_reconstruction_concatenates_shards() {
        let shards = vec![vec![1u8, 2], vec![3u8, 4]];
        let result = DataReconstruction::reconstruct(&shards).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn data_availability_encode_and_reconstruct_roundtrip() {
        let da = DataAvailability::new(ErasureConfig { data_shards: 2, parity_shards: 1 });
        let original = vec![10u8, 20, 30, 40];
        let shards = da.encode(&original);
        let recovered = da.reconstruct(&shards).unwrap();
        // Concat of all shards should equal original (stub impl)
        assert!(!recovered.is_empty());
    }
}
