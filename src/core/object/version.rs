use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents version information for an object
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectVersion {
    /// Version number (increments with each update)
    number: u64,
    
    /// Transaction hash that created this version
    created_by: Vec<u8>,
    
    /// Previous version's transaction hash, if any
    previous_version: Option<Vec<u8>>,
    
    /// Creation timestamp of this version
    created_at: u64,
}

impl ObjectVersion {
    /// Creates a new object version
    pub fn new() -> Self {
        Self {
            number: 0,
            created_by: Vec::new(),
            previous_version: None,
            created_at: chrono::Utc::now().timestamp_millis() as u64,
        }
    }
    
    /// Creates a new object version with a specified transaction hash
    pub fn with_tx(tx_hash: Vec<u8>) -> Self {
        Self {
            number: 0,
            created_by: tx_hash,
            previous_version: None,
            created_at: chrono::Utc::now().timestamp_millis() as u64,
        }
    }
    
    /// Gets the version number
    pub fn number(&self) -> u64 {
        self.number
    }
    
    /// Gets the transaction hash that created this version
    pub fn created_by(&self) -> &Vec<u8> {
        &self.created_by
    }
    
    /// Gets the previous version's transaction hash, if any
    pub fn previous_version(&self) -> Option<&Vec<u8>> {
        self.previous_version.as_ref()
    }
    
    /// Gets the creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
    
    /// Increments the version number with a new transaction
    pub fn increment(&mut self, tx_hash: Vec<u8>) {
        let previous = std::mem::replace(&mut self.created_by, tx_hash);
        self.previous_version = if previous.is_empty() { None } else { Some(previous) };
        self.number += 1;
        self.created_at = chrono::Utc::now().timestamp_millis() as u64;
    }
    
    /// Converts the version to bytes for hashing
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Add number
        result.extend_from_slice(&self.number.to_le_bytes());
        
        // Add created_by
        result.extend_from_slice(&self.created_by);
        
        // Add previous_version if it exists
        if let Some(ref prev) = self.previous_version {
            result.extend_from_slice(prev);
        }
        
        // Add created_at
        result.extend_from_slice(&self.created_at.to_le_bytes());
        
        result
    }
}

impl Default for ObjectVersion {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ObjectVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectVersion")
            .field("number", &self.number)
            .field("created_by", &hex::encode(&self.created_by))
            .field("previous_version", &self.previous_version.as_ref().map(hex::encode))
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_object_version_new() {
        let version = ObjectVersion::new();
        assert_eq!(version.number, 0);
        assert!(version.created_by.is_empty());
        assert!(version.previous_version.is_none());
    }
    
    #[test]
    fn test_object_version_with_tx() {
        let tx_hash = vec![1, 2, 3, 4];
        let version = ObjectVersion::with_tx(tx_hash.clone());
        assert_eq!(version.number, 0);
        assert_eq!(version.created_by, tx_hash);
        assert!(version.previous_version.is_none());
    }
    
    #[test]
    fn test_object_version_increment() {
        let tx1_hash = vec![1, 2, 3, 4];
        let tx2_hash = vec![5, 6, 7, 8];
        
        let mut version = ObjectVersion::with_tx(tx1_hash.clone());
        assert_eq!(version.number, 0);
        
        version.increment(tx2_hash.clone());
        assert_eq!(version.number, 1);
        assert_eq!(version.created_by, tx2_hash);
        assert_eq!(version.previous_version, Some(tx1_hash));
    }
    
    #[test]
    fn test_object_version_to_bytes() {
        let tx_hash = vec![1, 2, 3, 4];
        let version = ObjectVersion::with_tx(tx_hash.clone());
        
        let bytes = version.to_bytes();
        
        // Check that bytes contains number (8 bytes) + tx_hash (4 bytes) + created_at (8 bytes)
        assert_eq!(bytes.len(), 8 + 4 + 8);
        
        // Check number bytes
        assert_eq!(&bytes[0..8], &0u64.to_le_bytes());
        
        // Check tx_hash bytes
        assert_eq!(&bytes[8..12], &tx_hash);
    }
}
