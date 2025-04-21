use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::hash::{Hash, HashAlgorithm, Hashable};
use super::ObjectID;

/// Represents the state of an object at a specific point in time
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectState {
    /// The object ID this state belongs to
    object_id: ObjectID,
    
    /// Serialized data representing the object state
    data: Vec<u8>,
    
    /// Version number of this state
    version: u64,
    
    /// Transaction hash that created this state
    tx_hash: Vec<u8>,
    
    /// Timestamp when this state was created
    timestamp: u64,
    
    /// Hash of this state (optional, computed on demand)
    #[serde(skip)]
    hash: Option<Vec<u8>>,
}

impl ObjectState {
    /// Creates a new object state
    pub fn new(object_id: ObjectID, data: Vec<u8>, version: u64, tx_hash: Vec<u8>) -> Self {
        Self {
            object_id,
            data,
            version,
            tx_hash,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            hash: None,
        }
    }
    
    /// Gets the object ID
    pub fn object_id(&self) -> &ObjectID {
        &self.object_id
    }
    
    /// Gets the data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    
    /// Gets the version
    pub fn version(&self) -> u64 {
        self.version
    }
    
    /// Gets the transaction hash
    pub fn tx_hash(&self) -> &[u8] {
        &self.tx_hash
    }
    
    /// Gets the timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    
    /// Gets the hash of this state
    pub fn hash(&self) -> Vec<u8> {
        if let Some(ref hash) = self.hash {
            hash.clone()
        } else {
            self.calculate_hash()
        }
    }
    
    /// Calculates the hash of this state
    pub fn calculate_hash(&self) -> Vec<u8> {
        self.hash_with_algorithm(HashAlgorithm::SHA256).value
    }
    
    /// Updates the cached hash
    pub fn update_hash(&mut self) {
        let hash = self.calculate_hash();
        self.hash = Some(hash);
    }
}

impl Hashable for ObjectState {
    fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> Hash {
        let mut hasher = Hash::new_hasher(algorithm);
        
        hasher.update(&self.object_id.0);
        hasher.update(&self.data);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.tx_hash);
        hasher.update(&self.timestamp.to_le_bytes());
        
        Hash::new(algorithm, hasher.finalize())
    }
}

impl fmt::Debug for ObjectState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectState")
            .field("object_id", &hex::encode(&self.object_id.0))
            .field("data_size", &self.data.len())
            .field("version", &self.version)
            .field("tx_hash", &hex::encode(&self.tx_hash))
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_object_state_new() {
        let object_id = ObjectID(vec![1, 2, 3, 4]);
        let data = vec![5, 6, 7, 8];
        let version = 1;
        let tx_hash = vec![9, 10, 11, 12];
        
        let state = ObjectState::new(object_id.clone(), data.clone(), version, tx_hash.clone());
        
        assert_eq!(state.object_id(), &object_id);
        assert_eq!(state.data(), &data);
        assert_eq!(state.version(), version);
        assert_eq!(state.tx_hash(), &tx_hash);
    }
    
    #[test]
    fn test_object_state_hash() {
        let object_id = ObjectID(vec![1, 2, 3, 4]);
        let data = vec![5, 6, 7, 8];
        let version = 1;
        let tx_hash = vec![9, 10, 11, 12];
        
        let mut state = ObjectState::new(object_id, data.clone(), version, tx_hash.clone());
        
        // Initial hash calculation
        let hash1 = state.hash();
        
        // Same state should have the same hash
        let hash2 = state.hash();
        assert_eq!(hash1, hash2);
        
        // Update the state
        state = ObjectState::new(ObjectID(vec![1, 2, 3, 4]), vec![10, 11, 12, 13], 2, tx_hash);
        
        // Hash should be different
        let hash3 = state.hash();
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_object_state_hash_caching() {
        let object_id = ObjectID(vec![1, 2, 3, 4]);
        let data = vec![5, 6, 7, 8];
        let version = 1;
        let tx_hash = vec![9, 10, 11, 12];
        
        let mut state = ObjectState::new(object_id, data.clone(), version, tx_hash.clone());
        
        // Calculate hash and update cache
        let hash1 = state.calculate_hash();
        state.update_hash();
        
        // Cached hash should be used
        let hash2 = state.hash();
        assert_eq!(hash1, hash2);
    }
}
