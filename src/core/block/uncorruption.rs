use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Data specific to Proof of Uncorruption consensus
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfUncorruptionData {
    /// Uncorruption proof for the block
    pub uncorruption_proof: Vec<u8>,
    
    /// References to parallel chains, if any
    pub parallel_chain_refs: Vec<ParallelChainRef>,
    
    /// Validators who confirmed the block's uncorruption
    /// Map from validator ID to validator signature
    pub validator_confirmations: HashMap<Vec<u8>, Vec<u8>>,
    
    /// Number of confirmations required for uncorruption
    pub confirmation_threshold: u32,
    
    /// TEE attestation for the block execution
    pub tee_attestation: Option<Vec<u8>>,
    
    /// Additional proof data (algorithm-specific)
    pub proof_data: HashMap<String, Vec<u8>>,
}

impl ProofOfUncorruptionData {
    /// Creates a new empty ProofOfUncorruptionData
    pub fn new() -> Self {
        Self {
            uncorruption_proof: Vec::new(),
            parallel_chain_refs: Vec::new(),
            validator_confirmations: HashMap::new(),
            confirmation_threshold: 1,
            tee_attestation: None,
            proof_data: HashMap::new(),
        }
    }
    
    /// Creates a new ProofOfUncorruptionData with the given proof
    pub fn with_proof(uncorruption_proof: Vec<u8>) -> Self {
        let mut data = Self::new();
        data.uncorruption_proof = uncorruption_proof;
        data
    }
    
    /// Gets the uncorruption proof
    pub fn uncorruption_proof(&self) -> &[u8] {
        &self.uncorruption_proof
    }
    
    /// Sets the uncorruption proof
    pub fn set_uncorruption_proof(&mut self, proof: Vec<u8>) {
        self.uncorruption_proof = proof;
    }
    
    /// Gets the parallel chain references
    pub fn parallel_chain_refs(&self) -> &[ParallelChainRef] {
        &self.parallel_chain_refs
    }
    
    /// Adds a parallel chain reference
    pub fn add_parallel_chain_ref(&mut self, reference: ParallelChainRef) {
        self.parallel_chain_refs.push(reference);
    }
    
    /// Gets the validator confirmations
    pub fn validator_confirmations(&self) -> &HashMap<Vec<u8>, Vec<u8>> {
        &self.validator_confirmations
    }
    
    /// Adds a validator confirmation
    pub fn add_validator_confirmation(&mut self, validator_id: Vec<u8>, signature: Vec<u8>) {
        self.validator_confirmations.insert(validator_id, signature);
    }
    
    /// Gets the number of validator confirmations
    pub fn confirmation_count(&self) -> usize {
        self.validator_confirmations.len()
    }
    
    /// Checks if the block has enough confirmations to meet the threshold
    pub fn has_threshold_confirmations(&self) -> bool {
        self.confirmation_count() >= self.confirmation_threshold as usize
    }
    
    /// Sets the confirmation threshold
    pub fn set_confirmation_threshold(&mut self, threshold: u32) {
        self.confirmation_threshold = threshold;
    }
    
    /// Gets the confirmation threshold
    pub fn confirmation_threshold(&self) -> u32 {
        self.confirmation_threshold
    }
    
    /// Gets the TEE attestation
    pub fn tee_attestation(&self) -> Option<&Vec<u8>> {
        self.tee_attestation.as_ref()
    }
    
    /// Sets the TEE attestation
    pub fn set_tee_attestation(&mut self, attestation: Vec<u8>) {
        self.tee_attestation = Some(attestation);
    }
    
    /// Checks if the data has a TEE attestation
    pub fn has_tee_attestation(&self) -> bool {
        self.tee_attestation.is_some()
    }
    
    /// Gets a proof data field by name
    pub fn get_proof_data(&self, name: &str) -> Option<&Vec<u8>> {
        self.proof_data.get(name)
    }
    
    /// Sets a proof data field
    pub fn set_proof_data(&mut self, name: String, data: Vec<u8>) {
        self.proof_data.insert(name, data);
    }
    
    /// Checks if the block has been confirmed by a specific validator
    pub fn is_confirmed_by(&self, validator_id: &[u8]) -> bool {
        self.validator_confirmations.contains_key(validator_id)
    }
    
    /// Verifies the uncorruption proof (placeholder for actual verification)
    pub fn verify_proof(&self) -> bool {
        // In a real implementation, this would verify the uncorruption proof
        // For now, we'll just check if the proof exists
        !self.uncorruption_proof.is_empty()
    }
    
    /// Merges confirmations from another uncorruption data object
    pub fn merge_confirmations(&mut self, other: &Self) {
        for (validator_id, signature) in &other.validator_confirmations {
            if !self.validator_confirmations.contains_key(validator_id) {
                self.validator_confirmations.insert(validator_id.clone(), signature.clone());
            }
        }
    }
    
    /// Clears all confirmations
    pub fn clear_confirmations(&mut self) {
        self.validator_confirmations.clear();
    }
}

impl Default for ProofOfUncorruptionData {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ProofOfUncorruptionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProofOfUncorruptionData")
            .field("uncorruption_proof", &format!("{}bytes", self.uncorruption_proof.len()))
            .field("parallel_chain_refs", &self.parallel_chain_refs)
            .field("validator_confirmations", &self.confirmation_count())
            .field("confirmation_threshold", &self.confirmation_threshold)
            .field("has_tee_attestation", &self.has_tee_attestation())
            .field("proof_data_fields", &self.proof_data.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Reference to a parallel chain in the PoU model
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParallelChainRef {
    /// Chain identifier
    pub chain_id: Vec<u8>,
    
    /// Block hash in the parallel chain
    pub block_hash: Vec<u8>,
    
    /// Reference type
    pub ref_type: ParallelChainRefType,
}

impl ParallelChainRef {
    /// Creates a new parallel chain reference
    pub fn new(chain_id: Vec<u8>, block_hash: Vec<u8>) -> Self {
        Self {
            chain_id,
            block_hash,
            ref_type: ParallelChainRefType::Standard,
        }
    }
    
    /// Creates a new parallel chain reference with a specific type
    pub fn with_type(chain_id: Vec<u8>, block_hash: Vec<u8>, ref_type: ParallelChainRefType) -> Self {
        Self {
            chain_id,
            block_hash,
            ref_type,
        }
    }
}

/// Type of parallel chain reference in the PoU model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParallelChainRefType {
    /// Standard reference
    Standard,
    
    /// Uncorruption proof reference
    UncorruptionProof,
    
    /// Checkpoint reference
    Checkpoint,
    
    /// Custom reference type
    Custom(u16),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pou_data_creation() {
        // Test default constructor
        let data = ProofOfUncorruptionData::new();
        
        assert!(data.uncorruption_proof().is_empty());
        assert!(data.parallel_chain_refs().is_empty());
        assert_eq!(data.confirmation_count(), 0);
        assert_eq!(data.confirmation_threshold(), 1);
        assert!(!data.has_tee_attestation());
        
        // Test with_proof constructor
        let proof = vec![1, 2, 3, 4];
        let data = ProofOfUncorruptionData::with_proof(proof.clone());
        
        assert_eq!(data.uncorruption_proof(), &proof);
    }
    
    #[test]
    fn test_pou_data_validator_confirmations() {
        let mut data = ProofOfUncorruptionData::new();
        
        // Add validator confirmations
        let validator1 = vec![1, 1, 1, 1];
        let signature1 = vec![10, 10, 10, 10];
        let validator2 = vec![2, 2, 2, 2];
        let signature2 = vec![20, 20, 20, 20];
        
        data.add_validator_confirmation(validator1.clone(), signature1.clone());
        assert_eq!(data.confirmation_count(), 1);
        assert!(data.is_confirmed_by(&validator1));
        
        data.add_validator_confirmation(validator2.clone(), signature2.clone());
        assert_eq!(data.confirmation_count(), 2);
        assert!(data.is_confirmed_by(&validator2));
        
        // Set a higher threshold
        data.set_confirmation_threshold(3);
        assert_eq!(data.confirmation_threshold(), 3);
        assert!(!data.has_threshold_confirmations());
        
        // Lower the threshold to match our confirmations
        data.set_confirmation_threshold(2);
        assert!(data.has_threshold_confirmations());
        
        // Clear confirmations
        data.clear_confirmations();
        assert_eq!(data.confirmation_count(), 0);
        assert!(!data.is_confirmed_by(&validator1));
    }
    
    #[test]
    fn test_pou_data_tee_attestation() {
        let mut data = ProofOfUncorruptionData::new();
        
        // Initially no attestation
        assert!(!data.has_tee_attestation());
        
        // Add attestation
        let attestation = vec![1, 2, 3, 4];
        data.set_tee_attestation(attestation.clone());
        
        assert!(data.has_tee_attestation());
        assert_eq!(data.tee_attestation(), Some(&attestation));
    }
    
    #[test]
    fn test_pou_data_proof_data() {
        let mut data = ProofOfUncorruptionData::new();
        
        // Add proof data
        let field_name = "test_field".to_string();
        let field_data = vec![1, 2, 3, 4];
        
        data.set_proof_data(field_name.clone(), field_data.clone());
        
        assert_eq!(data.get_proof_data(&field_name), Some(&field_data));
        assert_eq!(data.get_proof_data("nonexistent"), None);
    }
    
    #[test]
    fn test_pou_data_merge_confirmations() {
        let mut data1 = ProofOfUncorruptionData::new();
        let mut data2 = ProofOfUncorruptionData::new();
        
        // Add different confirmations to each
        let validator1 = vec![1, 1, 1, 1];
        let signature1 = vec![10, 10, 10, 10];
        let validator2 = vec![2, 2, 2, 2];
        let signature2 = vec![20, 20, 20, 20];
        
        data1.add_validator_confirmation(validator1.clone(), signature1.clone());
        data2.add_validator_confirmation(validator2.clone(), signature2.clone());
        
        // Merge confirmations
        data1.merge_confirmations(&data2);
        
        assert_eq!(data1.confirmation_count(), 2);
        assert!(data1.is_confirmed_by(&validator1));
        assert!(data1.is_confirmed_by(&validator2));
        
        // data2 should be unchanged
        assert_eq!(data2.confirmation_count(), 1);
        assert!(!data2.is_confirmed_by(&validator1));
        assert!(data2.is_confirmed_by(&validator2));
    }
    
    #[test]
    fn test_parallel_chain_ref() {
        let chain_id = vec![1, 2, 3, 4];
        let block_hash = vec![5, 6, 7, 8];
        
        // Test standard constructor
        let reference = ParallelChainRef::new(chain_id.clone(), block_hash.clone());
        
        assert_eq!(reference.chain_id, chain_id);
        assert_eq!(reference.block_hash, block_hash);
        assert_eq!(reference.ref_type, ParallelChainRefType::Standard);
        
        // Test with_type constructor
        let ref_type = ParallelChainRefType::UncorruptionProof;
        let reference = ParallelChainRef::with_type(
            chain_id.clone(),
            block_hash.clone(),
            ref_type,
        );
        
        assert_eq!(reference.chain_id, chain_id);
        assert_eq!(reference.block_hash, block_hash);
        assert_eq!(reference.ref_type, ref_type);
    }
}
