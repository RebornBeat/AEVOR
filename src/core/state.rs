use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::core::merkle::MerkleTree;
use crate::core::object::{Object, ObjectID, ObjectStatus};
use crate::error::{AevorError, Result};

/// Represents the global state of the blockchain
#[derive(Clone)]
pub struct GlobalState {
    /// Current block height
    current_height: u64,
    
    /// Merkle tree of the current state
    state_tree: MerkleTree,
    
    /// State snapshots at various heights
    snapshots: HashMap<u64, StateSnapshot>,
    
    /// Objects in the current state
    objects: HashMap<ObjectID, Object>,
    
    /// Objects in superposition
    superpositioned_objects: HashMap<ObjectID, Object>,
}

impl GlobalState {
    /// Creates a new global state
    pub fn new() -> Self {
        Self {
            current_height: 0,
            state_tree: MerkleTree::from_leaves(Vec::new()),
            snapshots: HashMap::new(),
            objects: HashMap::new(),
            superpositioned_objects: HashMap::new(),
        }
    }
    
    /// Gets the current height
    pub fn current_height(&self) -> u64 {
        self.current_height
    }
    
    /// Sets the current height
    pub fn set_current_height(&mut self, height: u64) {
        self.current_height = height;
    }
    
    /// Gets the Merkle root of the current state
    pub fn state_root(&self) -> Vec<u8> {
        self.state_tree.root().to_vec()
    }
    
    /// Gets an object by ID
    pub fn get_object(&self, id: &ObjectID) -> Option<&Object> {
        self.objects.get(id)
    }
    
    /// Gets a mutable reference to an object
    pub fn get_object_mut(&mut self, id: &ObjectID) -> Option<&mut Object> {
        self.objects.get_mut(id)
    }
    
    /// Puts an object into the state
    pub fn put_object(&mut self, object: Object) -> Result<()> {
        let id = object.id().clone();
        
        // Add the object
        self.objects.insert(id, object);
        
        // Update the state tree
        self.update_state_tree();
        
        Ok(())
    }
    
    /// Removes an object from the state
    pub fn delete_object(&mut self, id: &ObjectID) -> Result<()> {
        // Check if the object exists
        if !self.objects.contains_key(id) {
            return Err(AevorError::validation(format!("Object not found: {}", hex::encode(&id.0))));
        }
        
        // Remove the object
        self.objects.remove(id);
        
        // Update the state tree
        self.update_state_tree();
        
        Ok(())
    }
    
    /// Gets a superpositioned object by ID
    pub fn get_superpositioned_object(&self, id: &ObjectID) -> Option<&Object> {
        self.superpositioned_objects.get(id)
    }
    
    /// Gets a mutable reference to a superpositioned object
    pub fn get_superpositioned_object_mut(&mut self, id: &ObjectID) -> Option<&mut Object> {
        self.superpositioned_objects.get_mut(id)
    }
    
    /// Puts an object into superposition
    pub fn put_superpositioned_object(&mut self, object: Object) -> Result<()> {
        let id = object.id().clone();
        
        // Add the object
        self.superpositioned_objects.insert(id, object);
        
        Ok(())
    }
    
    /// Collapses a superpositioned object to a specific state
    pub fn collapse_superposition(&mut self, id: &ObjectID, state_index: usize) -> Result<()> {
        // Check if the object exists in superposition
        let object = match self.superpositioned_objects.remove(id) {
            Some(obj) => obj,
            None => return Err(AevorError::validation(format!("Object not in superposition: {}", hex::encode(&id.0)))),
        };
        
        // Check if the object is actually in superposition
        if !object.is_in_superposition() {
            return Err(AevorError::validation(format!("Object is not in superposition: {}", hex::encode(&id.0))));
        }
        
        // Collapse the superposition
        let mut collapsed_object = object.clone();
        collapsed_object.collapse_superposition(state_index)?;
        
        // Put the collapsed object in the regular state
        self.put_object(collapsed_object)?;
        
        Ok(())
    }
    
    /// Gets all objects
    pub fn get_all_objects(&self) -> &HashMap<ObjectID, Object> {
        &self.objects
    }
    
    /// Gets all superpositioned objects
    pub fn get_all_superpositioned_objects(&self) -> &HashMap<ObjectID, Object> {
        &self.superpositioned_objects
    }
    
    /// Creates a snapshot of the current state
    pub fn create_snapshot(&mut self) -> StateSnapshot {
        let snapshot = StateSnapshot {
            height: self.current_height,
            state_root: self.state_root(),
            objects: self.objects.values().cloned().collect(),
            validator_set: Vec::new(),
        };
        
        self.snapshots.insert(self.current_height, snapshot.clone());
        
        snapshot
    }
    
    /// Gets a state snapshot by height
    pub fn get_snapshot(&self, height: u64) -> Option<&StateSnapshot> {
        self.snapshots.get(&height)
    }
    
    /// Gets the latest state snapshot
    pub fn get_latest_snapshot(&self) -> Option<&StateSnapshot> {
        self.snapshots.get(&self.current_height)
    }
    
    /// Checks if an object exists
    pub fn object_exists(&self, id: &ObjectID) -> bool {
        self.objects.contains_key(id)
    }
    
    /// Checks if an object is in superposition
    pub fn is_in_superposition(&self, id: &ObjectID) -> bool {
        self.superpositioned_objects.contains_key(id)
    }
    
    /// Updates the state tree based on current objects
    fn update_state_tree(&mut self) {
        // Collect object hashes
        let mut object_hashes = Vec::new();
        for object in self.objects.values() {
            object_hashes.push(object.calculate_hash());
        }
        
        // Create a new state tree
        self.state_tree = MerkleTree::from_leaves(object_hashes);
    }
}

impl fmt::Debug for GlobalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalState")
            .field("current_height", &self.current_height)
            .field("state_root", &hex::encode(self.state_root()))
            .field("object_count", &self.objects.len())
            .field("superpositioned_object_count", &self.superpositioned_objects.len())
            .field("snapshot_count", &self.snapshots.len())
            .finish()
    }
}

/// Represents a snapshot of the global state at a specific block height
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Block height of the snapshot
    pub height: u64,
    
    /// Merkle root of the state
    pub state_root: Vec<u8>,
    
    /// List of objects in the state
    pub objects: Vec<Object>,
    
    /// List of validators at this state
    pub validator_set: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::object::{Object, ObjectID, ObjectType};
    
    #[test]
    fn test_global_state_basic() {
        let mut state = GlobalState::new();
        
        // Initial state
        assert_eq!(state.current_height(), 0);
        assert!(state.get_all_objects().is_empty());
        assert!(state.get_all_superpositioned_objects().is_empty());
        
        // Set height
        state.set_current_height(10);
        assert_eq!(state.current_height(), 10);
    }
    
    #[test]
    fn test_global_state_objects() {
        let mut state = GlobalState::new();
        
        // Create a test object
        let owner = vec![1, 2, 3, 4];
        let object = Object::new(owner.clone(), ObjectType::Regular);
        let object_id = object.id().clone();
        
        // Put object in state
        state.put_object(object.clone()).unwrap();
        
        // Get object
        let stored_object = state.get_object(&object_id).unwrap();
        assert_eq!(stored_object.owner(), &owner);
        
        // Check object exists
        assert!(state.object_exists(&object_id));
        
        // Delete object
        state.delete_object(&object_id).unwrap();
        
        // Check object no longer exists
        assert!(!state.object_exists(&object_id));
        assert!(state.get_object(&object_id).is_none());
    }
    
    #[test]
    fn test_global_state_superposition() {
        let mut state = GlobalState::new();
        
        // Create a test object
        let owner = vec![1, 2, 3, 4];
        let mut object = Object::new(owner.clone(), ObjectType::Regular);
        let object_id = object.id().clone();
        
        // Enter superposition
        object.enter_superposition().unwrap();
        
        // Create two potential states
        let mut state1 = object.clone();
        state1.set_data(vec![1, 1, 1, 1]);
        
        let mut state2 = object.clone();
        state2.set_data(vec![2, 2, 2, 2]);
        
        // Add potential states
        let tx1_hash = vec![1, 1, 1, 1];
        let tx2_hash = vec![2, 2, 2, 2];
        
        let idx1 = object.add_potential_state(tx1_hash.clone(), state1).unwrap();
        let idx2 = object.add_potential_state(tx2_hash.clone(), state2).unwrap();
        
        // Put object in superposition
        state.put_superpositioned_object(object.clone()).unwrap();
        
        // Check object is in superposition
        assert!(state.is_in_superposition(&object_id));
        assert!(state.get_superpositioned_object(&object_id).is_some());
        
        // Collapse superposition
        state.collapse_superposition(&object_id, idx1).unwrap();
        
        // Check object is now in regular state and not in superposition
        assert!(!state.is_in_superposition(&object_id));
        assert!(state.object_exists(&object_id));
        
        // Verify the collapsed state
        let collapsed_object = state.get_object(&object_id).unwrap();
        assert_eq!(collapsed_object.data(), &vec![1, 1, 1, 1]);
    }
    
    #[test]
    fn test_global_state_snapshot() {
        let mut state = GlobalState::new();
        
        // Create test objects
        let owner = vec![1, 2, 3, 4];
        let object1 = Object::new(owner.clone(), ObjectType::Regular);
        let object2 = Object::new(owner.clone(), ObjectType::Token);
        
        // Put objects in state
        state.put_object(object1).unwrap();
        state.put_object(object2).unwrap();
        
        // Set height
        state.set_current_height(5);
        
        // Create snapshot
        let snapshot = state.create_snapshot();
        
        // Verify snapshot
        assert_eq!(snapshot.height, 5);
        assert_eq!(snapshot.objects.len(), 2);
        assert_eq!(snapshot.state_root, state.state_root());
        
        // Get snapshot
        let stored_snapshot = state.get_snapshot(5).unwrap();
        assert_eq!(stored_snapshot.height, 5);
        assert_eq!(stored_snapshot.objects.len(), 2);
        
        // Get latest snapshot
        let latest_snapshot = state.get_latest_snapshot().unwrap();
        assert_eq!(latest_snapshot.height, 5);
    }
}
