use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::error::{AevorError, Result};
use super::Object;

/// Represents a candidate state in a superposition
#[derive(Clone, Serialize, Deserialize)]
pub struct StateCandidate {
    /// The state object
    pub state: Object,
    
    /// Cryptographic hash of the state
    pub hash: Vec<u8>,
    
    /// Index in the potential states list
    pub index: usize,
    
    /// Transaction hash that created this state
    pub tx_hash: Vec<u8>,
    
    /// Timestamp when this candidate was added
    pub timestamp: u64,
}

impl StateCandidate {
    /// Creates a new state candidate
    pub fn new(state: Object, tx_hash: Vec<u8>, index: usize) -> Self {
        let hash = state.calculate_hash();
        
        Self {
            state,
            hash,
            index,
            tx_hash,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }
}

impl fmt::Debug for StateCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateCandidate")
            .field("hash", &hex::encode(&self.hash))
            .field("index", &self.index)
            .field("tx_hash", &hex::encode(&self.tx_hash))
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Represents a superpositioned state that can exist in multiple
/// potential states until finalized
#[derive(Clone, Serialize, Deserialize)]
pub struct SuperpositionedState {
    /// Unique identifier for this superpositioned state
    id: String,
    
    /// Current potential states with their cryptographic hashes
    potential_states: Vec<StateCandidate>,
    
    /// Whether this state has been finalized
    finalized: bool,
    
    /// The selected state after finalization
    finalized_state_index: Option<usize>,
    
    /// Finalization threshold (number of validator signatures required)
    threshold: usize,
    
    /// Creation timestamp
    creation_time: u64,
    
    /// Finalization deadline
    finalization_deadline: u64,
    
    /// Validator signatures for each state candidate
    /// Map structure: state_index -> (validator_id -> signature)
    validator_signatures: HashMap<usize, HashMap<Vec<u8>, Vec<u8>>>,
}

impl SuperpositionedState {
    /// Creates a new superpositioned state with an initial state
    pub fn new(initial_state: Object) -> Self {
        let id = format!("superposition-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().timestamp_millis() as u64;
        
        // Create initial state candidate
        let initial_candidate = StateCandidate::new(
            initial_state,
            Vec::new(), // No transaction for the initial state
            0, // Index 0 is the original state
        );
        
        // Initialize empty validator signatures map for the initial state
        let mut validator_signatures = HashMap::new();
        validator_signatures.insert(0, HashMap::new());
        
        Self {
            id,
            potential_states: vec![initial_candidate],
            finalized: false,
            finalized_state_index: None,
            threshold: 2, // Default threshold
            creation_time: now,
            finalization_deadline: now + 60000, // 1 minute deadline by default
            validator_signatures,
        }
    }
    
    /// Gets the unique identifier
    pub fn id(&self) -> &str {
        &self.id
    }
    
    /// Adds a potential state to the superposition
    pub fn add_state(&mut self, tx_hash: Vec<u8>, state: Object) -> usize {
        let index = self.potential_states.len();
        
        // Create a state candidate
        let candidate = StateCandidate::new(state, tx_hash, index);
        
        // Add to potential states
        self.potential_states.push(candidate);
        
        // Initialize empty validator signatures map for this state
        self.validator_signatures.insert(index, HashMap::new());
        
        index
    }
    
    /// Adds a validator confirmation for a specific state
    pub fn add_validator_confirmation(&mut self, state_index: usize, validator_id: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        // Check if the state index is valid
        if state_index >= self.potential_states.len() {
            return Err(AevorError::object_versioning(format!("Invalid state index: {}", state_index)));
        }
        
        // Add validator signature
        let signatures = self.validator_signatures.get_mut(&state_index).unwrap();
        signatures.insert(validator_id, signature);
        
        // Check if we have reached the threshold for this state
        if signatures.len() >= self.threshold {
            // If this is the first state to reach the threshold, finalize it
            if !self.finalized {
                self.finalized = true;
                self.finalized_state_index = Some(state_index);
            }
        }
        
        Ok(())
    }
    
    /// Gets all potential states
    pub fn potential_states(&self) -> &[StateCandidate] {
        &self.potential_states
    }
    
    /// Gets a specific state by index
    pub fn get_state(&self, index: usize) -> Option<&StateCandidate> {
        self.potential_states.get(index)
    }
    
    /// Gets the original state (index 0)
    pub fn original_state(&self) -> &StateCandidate {
        &self.potential_states[0]
    }
    
    /// Gets the finalized state, if any
    pub fn finalized_state(&self) -> Option<&StateCandidate> {
        self.finalized_state_index.and_then(|index| self.potential_states.get(index))
    }
    
    /// Checks if the state has been finalized
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }
    
    /// Gets the validator signatures for a specific state
    pub fn validator_signatures(&self, state_index: usize) -> Option<&HashMap<Vec<u8>, Vec<u8>>> {
        self.validator_signatures.get(&state_index)
    }
    
    /// Gets the number of validator signatures for a specific state
    pub fn signature_count(&self, state_index: usize) -> usize {
        self.validator_signatures.get(&state_index).map_or(0, |sigs| sigs.len())
    }
    
    /// Gets the total number of potential states
    pub fn state_count(&self) -> usize {
        self.potential_states.len()
    }
    
    /// Gets the validation status for all states
    pub fn validation_status(&self) -> HashMap<usize, usize> {
        let mut result = HashMap::new();
        
        for (index, signatures) in &self.validator_signatures {
            result.insert(*index, signatures.len());
        }
        
        result
    }
    
    /// Checks if a state has reached validation threshold
    pub fn has_reached_threshold(&self, state_index: usize) -> bool {
        self.signature_count(state_index) >= self.threshold
    }
    
    /// Sets the validation threshold
    pub fn set_threshold(&mut self, threshold: usize) {
        self.threshold = threshold;
    }
    
    /// Gets the creation timestamp
    pub fn creation_time(&self) -> u64 {
        self.creation_time
    }
    
    /// Gets the finalization deadline
    pub fn finalization_deadline(&self) -> u64 {
        self.finalization_deadline
    }
    
    /// Sets the finalization deadline
    pub fn set_finalization_deadline(&mut self, deadline: u64) {
        self.finalization_deadline = deadline;
    }
    
    /// Checks if the superposition has expired (past deadline)
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        now > self.finalization_deadline
    }
    
    /// Collapses the superposition to a specific state
    pub fn collapse(&self, state_index: usize) -> Result<(Object, Vec<u8>)> {
        // Check if the state index is valid
        if state_index >= self.potential_states.len() {
            return Err(AevorError::object_versioning(format!("Invalid state index: {}", state_index)));
        }
        
        // Get the selected state
        let state_candidate = &self.potential_states[state_index];
        
        // Return a clone of the state and the transaction hash
        Ok((state_candidate.state.clone(), state_candidate.tx_hash.clone()))
    }
    
    /// Collapses the superposition to the state with the most validator confirmations
    pub fn collapse_to_most_confirmed(&self) -> Result<(Object, Vec<u8>)> {
        let mut max_signatures = 0;
        let mut max_index = 0;
        
        for (index, signatures) in &self.validator_signatures {
            if signatures.len() > max_signatures {
                max_signatures = signatures.len();
                max_index = *index;
            }
        }
        
        self.collapse(max_index)
    }
    
    /// Checks if a specific validator has confirmed a specific state
    pub fn is_confirmed_by(&self, state_index: usize, validator_id: &[u8]) -> bool {
        self.validator_signatures.get(&state_index)
            .map_or(false, |sigs| sigs.contains_key(validator_id))
    }
}

impl fmt::Debug for SuperpositionedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SuperpositionedState")
            .field("id", &self.id)
            .field("potential_states", &self.potential_states.len())
            .field("finalized", &self.finalized)
            .field("finalized_state_index", &self.finalized_state_index)
            .field("threshold", &self.threshold)
            .field("creation_time", &self.creation_time)
            .field("finalization_deadline", &self.finalization_deadline)
            .field("validator_signatures", &{
                let mut counts = HashMap::new();
                for (index, sigs) in &self.validator_signatures {
                    counts.insert(index, sigs.len());
                }
                counts
            })
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::object::{Object, ObjectType};
    
    #[test]
    fn test_superpositioned_state_new() {
        let initial_state = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        let superposition = SuperpositionedState::new(initial_state.clone());
        
        assert_eq!(superposition.state_count(), 1);
        assert!(!superposition.is_finalized());
        assert!(superposition.finalized_state_index.is_none());
        
        // Check original state
        let original = superposition.original_state();
        assert_eq!(original.index, 0);
        assert_eq!(original.state.owner(), initial_state.owner());
    }
    
    #[test]
    fn test_add_state() {
        let initial_state = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        let mut superposition = SuperpositionedState::new(initial_state);
        
        // Create a new state
        let mut state1 = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        state1.set_data(vec![5, 6, 7, 8]);
        
        // Add the state
        let tx_hash = vec![10, 11, 12, 13];
        let index = superposition.add_state(tx_hash.clone(), state1.clone());
        
        assert_eq!(index, 1);
        assert_eq!(superposition.state_count(), 2);
        
        // Check the added state
        let added_state = superposition.get_state(index).unwrap();
        assert_eq!(added_state.index, index);
        assert_eq!(added_state.tx_hash, tx_hash);
        assert_eq!(added_state.state.data(), state1.data());
    }
    
    #[test]
    fn test_validator_confirmations() {
        let initial_state = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        let mut superposition = SuperpositionedState::new(initial_state);
        
        // Create a new state
        let mut state1 = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        state1.set_data(vec![5, 6, 7, 8]);
        
        // Add the state
        let tx_hash = vec![10, 11, 12, 13];
        let index = superposition.add_state(tx_hash, state1);
        
        // Add validator confirmations
        let validator1 = vec![1, 1, 1, 1];
        let validator2 = vec![2, 2, 2, 2];
        
        assert!(superposition.add_validator_confirmation(index, validator1.clone(), vec![1]).is_ok());
        assert_eq!(superposition.signature_count(index), 1);
        assert!(superposition.is_confirmed_by(index, &validator1));
        
        assert!(superposition.add_validator_confirmation(index, validator2.clone(), vec![2]).is_ok());
        assert_eq!(superposition.signature_count(index), 2);
        
        // The threshold is 2, so the state should now be finalized
        assert!(superposition.is_finalized());
        assert_eq!(superposition.finalized_state_index, Some(index));
    }
    
    #[test]
    fn test_collapse() {
        let initial_state = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        let mut superposition = SuperpositionedState::new(initial_state);
        
        // Create two new states
        let mut state1 = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        state1.set_data(vec![5, 6, 7, 8]);
        
        let mut state2 = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        state2.set_data(vec![9, 10, 11, 12]);
        
        // Add the states
        let tx1_hash = vec![10, 11, 12, 13];
        let tx2_hash = vec![20, 21, 22, 23];
        
        let index1 = superposition.add_state(tx1_hash.clone(), state1.clone());
        let index2 = superposition.add_state(tx2_hash.clone(), state2.clone());
        
        // Collapse to state1
        let (collapsed_state, tx_hash) = superposition.collapse(index1).unwrap();
        
        assert_eq!(collapsed_state.data(), state1.data());
        assert_eq!(tx_hash, tx1_hash);
        
        // Try to collapse to an invalid index
        let result = superposition.collapse(10);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_collapse_to_most_confirmed() {
        let initial_state = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        let mut superposition = SuperpositionedState::new(initial_state);
        
        // Create two new states
        let mut state1 = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        state1.set_data(vec![5, 6, 7, 8]);
        
        let mut state2 = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        state2.set_data(vec![9, 10, 11, 12]);
        
        // Add the states
        let tx1_hash = vec![10, 11, 12, 13];
        let tx2_hash = vec![20, 21, 22, 23];
        
        let index1 = superposition.add_state(tx1_hash.clone(), state1.clone());
        let index2 = superposition.add_state(tx2_hash.clone(), state2.clone());
        
        // Add more confirmations to state2
        superposition.add_validator_confirmation(index2, vec![1, 1, 1, 1], vec![1]).unwrap();
        superposition.add_validator_confirmation(index2, vec![2, 2, 2, 2], vec![2]).unwrap();
        superposition.add_validator_confirmation(index2, vec![3, 3, 3, 3], vec![3]).unwrap();
        
        // Add fewer confirmations to state1
        superposition.add_validator_confirmation(index1, vec![4, 4, 4, 4], vec![4]).unwrap();
        
        // Collapse to most confirmed state (should be state2)
        let (collapsed_state, tx_hash) = superposition.collapse_to_most_confirmed().unwrap();
        
        assert_eq!(collapsed_state.data(), state2.data());
        assert_eq!(tx_hash, tx2_hash);
    }
    
    #[test]
    fn test_expiration() {
        let initial_state = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        let mut superposition = SuperpositionedState::new(initial_state);
        
        // Set a deadline in the past
        let past_deadline = chrono::Utc::now().timestamp_millis() as u64 - 1000;
        superposition.set_finalization_deadline(past_deadline);
        
        assert!(superposition.is_expired());
        
        // Set a deadline in the future
        let future_deadline = chrono::Utc::now().timestamp_millis() as u64 + 60000;
        superposition.set_finalization_deadline(future_deadline);
        
        assert!(!superposition.is_expired());
    }
}
