use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents a reference to a block in a parallel chain in the macro-DAG
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParallelChainReference {
    /// Chain identifier
    pub chain_id: Vec<u8>,
    
    /// Block hash being referenced
    pub block_hash: Vec<u8>,
    
    /// Block height being referenced
    pub height: u64,
    
    /// Reference type (cross-chain reference purpose)
    pub reference_type: ReferenceType,
    
    /// Optional reference data
    pub data: Vec<u8>,
}

impl ParallelChainReference {
    /// Creates a new parallel chain reference
    pub fn new(chain_id: Vec<u8>, block_hash: Vec<u8>, height: u64) -> Self {
        Self {
            chain_id,
            block_hash,
            height,
            reference_type: ReferenceType::Standard,
            data: Vec::new(),
        }
    }
    
    /// Creates a new parallel chain reference with a specific reference type
    pub fn with_type(chain_id: Vec<u8>, block_hash: Vec<u8>, height: u64, reference_type: ReferenceType) -> Self {
        Self {
            chain_id,
            block_hash,
            height,
            reference_type,
            data: Vec::new(),
        }
    }
    
    /// Creates a new parallel chain reference with additional data
    pub fn with_data(chain_id: Vec<u8>, block_hash: Vec<u8>, height: u64, reference_type: ReferenceType, data: Vec<u8>) -> Self {
        Self {
            chain_id,
            block_hash,
            height,
            reference_type,
            data,
        }
    }
    
    /// Gets the chain ID
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }
    
    /// Gets the block hash
    pub fn block_hash(&self) -> &[u8] {
        &self.block_hash
    }
    
    /// Gets the block height
    pub fn height(&self) -> u64 {
        self.height
    }
    
    /// Gets the reference type
    pub fn reference_type(&self) -> ReferenceType {
        self.reference_type
    }
    
    /// Gets the reference data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    
    /// Sets the reference data
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }
    
    /// Sets the reference type
    pub fn set_reference_type(&mut self, reference_type: ReferenceType) {
        self.reference_type = reference_type;
    }
}

impl fmt::Debug for ParallelChainReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParallelChainReference")
            .field("chain_id", &hex::encode(&self.chain_id))
            .field("block_hash", &hex::encode(&self.block_hash))
            .field("height", &self.height)
            .field("reference_type", &self.reference_type)
            .field("data", &format!("{}bytes", self.data.len()))
            .finish()
    }
}

/// Type of parallel chain reference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReferenceType {
    /// Standard reference (basic fork merging)
    Standard,
    
    /// Finality reference (confirms finality in another chain)
    Finality,
    
    /// State reference (refers to specific state commitment)
    State,
    
    /// Cross-chain transaction reference
    CrossChainTx,
    
    /// Governance reference (related to protocol governance)
    Governance,
    
    /// Uncorruption proof reference
    UncorruptionProof,
    
    /// Custom reference type with a type ID
    Custom(u16),
}

impl fmt::Display for ReferenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReferenceType::Standard => write!(f, "Standard"),
            ReferenceType::Finality => write!(f, "Finality"),
            ReferenceType::State => write!(f, "State"),
            ReferenceType::CrossChainTx => write!(f, "CrossChainTx"),
            ReferenceType::Governance => write!(f, "Governance"),
            ReferenceType::UncorruptionProof => write!(f, "UncorruptionProof"),
            ReferenceType::Custom(id) => write!(f, "Custom-{}", id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parallel_chain_reference_creation() {
        let chain_id = vec![1, 2, 3, 4];
        let block_hash = vec![5, 6, 7, 8];
        let height = 10;
        
        // Test basic constructor
        let reference = ParallelChainReference::new(chain_id.clone(), block_hash.clone(), height);
        
        assert_eq!(reference.chain_id(), &chain_id);
        assert_eq!(reference.block_hash(), &block_hash);
        assert_eq!(reference.height(), height);
        assert_eq!(reference.reference_type(), ReferenceType::Standard);
        assert!(reference.data().is_empty());
        
        // Test with_type constructor
        let reference_type = ReferenceType::Finality;
        let reference = ParallelChainReference::with_type(
            chain_id.clone(),
            block_hash.clone(),
            height,
            reference_type,
        );
        
        assert_eq!(reference.chain_id(), &chain_id);
        assert_eq!(reference.block_hash(), &block_hash);
        assert_eq!(reference.height(), height);
        assert_eq!(reference.reference_type(), reference_type);
        assert!(reference.data().is_empty());
        
        // Test with_data constructor
        let data = vec![10, 11, 12, 13];
        let reference = ParallelChainReference::with_data(
            chain_id.clone(),
            block_hash.clone(),
            height,
            reference_type,
            data.clone(),
        );
        
        assert_eq!(reference.chain_id(), &chain_id);
        assert_eq!(reference.block_hash(), &block_hash);
        assert_eq!(reference.height(), height);
        assert_eq!(reference.reference_type(), reference_type);
        assert_eq!(reference.data(), &data);
    }
    
    #[test]
    fn test_parallel_chain_reference_setters() {
        let chain_id = vec![1, 2, 3, 4];
        let block_hash = vec![5, 6, 7, 8];
        let height = 10;
        
        let mut reference = ParallelChainReference::new(chain_id, block_hash, height);
        
        // Test set_reference_type
        let reference_type = ReferenceType::CrossChainTx;
        reference.set_reference_type(reference_type);
        assert_eq!(reference.reference_type(), reference_type);
        
        // Test set_data
        let data = vec![10, 11, 12, 13];
        reference.set_data(data.clone());
        assert_eq!(reference.data(), &data);
    }
    
    #[test]
    fn test_reference_type_display() {
        assert_eq!(format!("{}", ReferenceType::Standard), "Standard");
        assert_eq!(format!("{}", ReferenceType::Finality), "Finality");
        assert_eq!(format!("{}", ReferenceType::State), "State");
        assert_eq!(format!("{}", ReferenceType::CrossChainTx), "CrossChainTx");
        assert_eq!(format!("{}", ReferenceType::Governance), "Governance");
        assert_eq!(format!("{}", ReferenceType::UncorruptionProof), "UncorruptionProof");
        assert_eq!(format!("{}", ReferenceType::Custom(123)), "Custom-123");
    }
}
