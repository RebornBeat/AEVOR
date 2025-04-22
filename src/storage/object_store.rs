use std::collections::HashMap;
use std::sync::Arc;

use crate::core::object::{Object, ObjectID, ObjectStatus};
use crate::error::{AevorError, Result};
use crate::storage::database::{Database, Transaction};

/// Storage for blockchain objects
pub struct ObjectStore {
    /// Database instance
    db: Arc<dyn Database>,
    
    /// Objects column family name
    objects_cf: String,
    
    /// Objects by owner column family name
    objects_by_owner_cf: String,
    
    /// Objects by type column family name
    objects_by_type_cf: String,
    
    /// Superpositioned objects column family name
    superpositioned_objects_cf: String,
    
    /// Deleted objects column family name
    deleted_objects_cf: String,
    
    /// Objects by transaction column family name
    objects_by_tx_cf: String,
}

/// Object metadata for indexing
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ObjectMetadata {
    /// Object ID
    pub id: ObjectID,
    
    /// Object owner
    pub owner: Vec<u8>,
    
    /// Object type
    pub object_type: String,
    
    /// Object status
    pub status: ObjectStatus,
    
    /// Creation transaction hash
    pub creation_tx: Vec<u8>,
    
    /// Last update transaction hash
    pub update_tx: Vec<u8>,
    
    /// Creation timestamp
    pub created_at: u64,
    
    /// Last update timestamp
    pub updated_at: u64,
}

impl ObjectStore {
    /// Creates a new ObjectStore
    pub fn new(db: Arc<dyn Database>) -> Result<Self> {
        Ok(Self {
            db,
            objects_cf: "objects".to_string(),
            objects_by_owner_cf: "objects_by_owner".to_string(),
            objects_by_type_cf: "objects_by_type".to_string(),
            superpositioned_objects_cf: "superpositioned_objects".to_string(),
            deleted_objects_cf: "deleted_objects".to_string(),
            objects_by_tx_cf: "objects_by_tx".to_string(),
        })
    }
    
    /// Initializes the object store
    pub async fn initialize(&self) -> Result<()> {
        // Ensure all required column families exist
        if !self.db.column_family_exists(&self.objects_cf)? {
            self.db.create_column_family(&self.objects_cf)?;
        }
        
        if !self.db.column_family_exists(&self.objects_by_owner_cf)? {
            self.db.create_column_family(&self.objects_by_owner_cf)?;
        }
        
        if !self.db.column_family_exists(&self.objects_by_type_cf)? {
            self.db.create_column_family(&self.objects_by_type_cf)?;
        }
        
        if !self.db.column_family_exists(&self.superpositioned_objects_cf)? {
            self.db.create_column_family(&self.superpositioned_objects_cf)?;
        }
        
        if !self.db.column_family_exists(&self.deleted_objects_cf)? {
            self.db.create_column_family(&self.deleted_objects_cf)?;
        }
        
        if !self.db.column_family_exists(&self.objects_by_tx_cf)? {
            self.db.create_column_family(&self.objects_by_tx_cf)?;
        }
        
        Ok(())
    }
    
    /// Shuts down the object store
    pub async fn shutdown(&self) -> Result<()> {
        // Flush all pending writes
        self.db.flush()?;
        
        Ok(())
    }
    
    /// Puts an object in the store
    pub fn put_object(&self, object: &Object, tx_hash: Option<Vec<u8>>) -> Result<()> {
        // Create a transaction
        let mut txn = self.db.transaction();
        
        // Serialize the object
        let object_bytes = bincode::serialize(object)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize object: {}", e)))?;
        
        // Create metadata
        let metadata = ObjectMetadata {
            id: object.id().clone(),
            owner: object.owner().to_vec(),
            object_type: format!("{:?}", object.object_type()),
            status: object.status(),
            creation_tx: Vec::new(), // Will be updated if tx_hash is provided
            update_tx: tx_hash.clone().unwrap_or_default(),
            created_at: object.created_at(),
            updated_at: object.updated_at(),
        };
        
        // Store the object
        let object_key = object.id().0.clone();
        
        // Determine which column family to use based on status
        let cf = if object.status() == ObjectStatus::Superposition {
            &self.superpositioned_objects_cf
        } else if object.status() == ObjectStatus::Deleted {
            &self.deleted_objects_cf
        } else {
            &self.objects_cf
        };
        
        txn.put(cf, &object_key, &object_bytes)?;
        
        // Index by owner
        let owner_key = create_owner_key(&object.owner(), object.id());
        txn.put(&self.objects_by_owner_cf, &owner_key, &object_key)?;
        
        // Index by type
        let type_key = create_type_key(&format!("{:?}", object.object_type()), object.id());
        txn.put(&self.objects_by_type_cf, &type_key, &object_key)?;
        
        // Index by transaction if provided
        if let Some(hash) = tx_hash {
            let tx_key = create_tx_key(&hash, object.id());
            txn.put(&self.objects_by_tx_cf, &tx_key, &object_key)?;
        }
        
        // Execute the transaction
        self.db.execute_transaction(txn)?;
        
        Ok(())
    }
    
    /// Gets an object by ID
    pub fn get_object(&self, id: &ObjectID) -> Result<Option<Object>> {
        // Try to get from regular objects first
        if let Some(object_bytes) = self.db.get(&self.objects_cf, &id.0)? {
            return deserialize_object(&object_bytes);
        }
        
        // Try superpositioned objects next
        if let Some(object_bytes) = self.db.get(&self.superpositioned_objects_cf, &id.0)? {
            return deserialize_object(&object_bytes);
        }
        
        // Try deleted objects last
        if let Some(object_bytes) = self.db.get(&self.deleted_objects_cf, &id.0)? {
            return deserialize_object(&object_bytes);
        }
        
        Ok(None)
    }
    
    /// Gets objects by owner
    pub fn get_objects_by_owner(&self, owner: &[u8]) -> Result<Vec<Object>> {
        let mut result = Vec::new();
        let prefix = owner.to_vec();
        
        // Get all object IDs for this owner
        let iter = self.db.prefix_iterator(&self.objects_by_owner_cf, &prefix)?;
        
        for (_, value) in iter {
            if let Some(object) = self.get_object(&ObjectID(value))? {
                result.push(object);
            }
        }
        
        Ok(result)
    }
    
    /// Gets objects by type
    pub fn get_objects_by_type(&self, object_type: &str) -> Result<Vec<Object>> {
        let mut result = Vec::new();
        let prefix = object_type.as_bytes().to_vec();
        
        // Get all object IDs for this type
        let iter = self.db.prefix_iterator(&self.objects_by_type_cf, &prefix)?;
        
        for (_, value) in iter {
            if let Some(object) = self.get_object(&ObjectID(value))? {
                result.push(object);
            }
        }
        
        Ok(result)
    }
    
    /// Gets objects by transaction
    pub fn get_objects_by_transaction(&self, tx_hash: &[u8]) -> Result<Vec<Object>> {
        let mut result = Vec::new();
        let prefix = tx_hash.to_vec();
        
        // Get all object IDs for this transaction
        let iter = self.db.prefix_iterator(&self.objects_by_tx_cf, &prefix)?;
        
        for (_, value) in iter {
            if let Some(object) = self.get_object(&ObjectID(value))? {
                result.push(object);
            }
        }
        
        Ok(result)
    }
    
    /// Gets all superpositioned objects
    pub fn get_all_superpositioned_objects(&self) -> Result<Vec<Object>> {
        let mut result = Vec::new();
        
        // Get all superpositioned objects
        let iter = self.db.iterator(&self.superpositioned_objects_cf)?;
        
        for (_, value) in iter {
            if let Ok(Some(object)) = deserialize_object(&value) {
                result.push(object);
            }
        }
        
        Ok(result)
    }
    
    /// Deletes an object
    pub fn delete_object(&self, id: &ObjectID) -> Result<()> {
        // Get the object first to update metadata
        if let Some(object) = self.get_object(id)? {
            // Create a transaction
            let mut txn = self.db.transaction();
            
            // Remove from regular objects
            txn.delete(&self.objects_cf, &id.0)?;
            
            // Remove from superpositioned objects
            txn.delete(&self.superpositioned_objects_cf, &id.0)?;
            
            // Store in deleted objects with updated status if not already deleted
            if object.status() != ObjectStatus::Deleted {
                let mut deleted_object = object.clone();
                deleted_object.set_status(ObjectStatus::Deleted);
                
                let object_bytes = bincode::serialize(&deleted_object)
                    .map_err(|e| AevorError::serialization(format!("Failed to serialize object: {}", e)))?;
                
                txn.put(&self.deleted_objects_cf, &id.0, &object_bytes)?;
            }
            
            // Execute the transaction
            self.db.execute_transaction(txn)?;
        }
        
        Ok(())
    }
    
    /// Permanently removes an object
    pub fn purge_object(&self, id: &ObjectID) -> Result<()> {
        // Create a transaction
        let mut txn = self.db.transaction();
        
        // Remove from all column families
        txn.delete(&self.objects_cf, &id.0)?;
        txn.delete(&self.superpositioned_objects_cf, &id.0)?;
        txn.delete(&self.deleted_objects_cf, &id.0)?;
        
        // Remove from indexes
        // Note: This is inefficient as we have to scan all keys
        // A production implementation would use secondary indexes more efficiently
        
        // Owner index
        let iter = self.db.iterator(&self.objects_by_owner_cf)?;
        for (key, value) in iter {
            if value == id.0 {
                txn.delete(&self.objects_by_owner_cf, &key)?;
            }
        }
        
        // Type index
        let iter = self.db.iterator(&self.objects_by_type_cf)?;
        for (key, value) in iter {
            if value == id.0 {
                txn.delete(&self.objects_by_type_cf, &key)?;
            }
        }
        
        // Transaction index
        let iter = self.db.iterator(&self.objects_by_tx_cf)?;
        for (key, value) in iter {
            if value == id.0 {
                txn.delete(&self.objects_by_tx_cf, &key)?;
            }
        }
        
        // Execute the transaction
        self.db.execute_transaction(txn)?;
        
        Ok(())
    }
    
    /// Collapses a superpositioned object to a specific state
    pub fn collapse_superposition(&self, id: &ObjectID, final_object: &Object) -> Result<()> {
        // Create a transaction
        let mut txn = self.db.transaction();
        
        // Remove from superpositioned objects
        txn.delete(&self.superpositioned_objects_cf, &id.0)?;
        
        // Store the final object in regular objects
        let object_bytes = bincode::serialize(final_object)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize object: {}", e)))?;
        
        txn.put(&self.objects_cf, &id.0, &object_bytes)?;
        
        // Execute the transaction
        self.db.execute_transaction(txn)?;
        
        Ok(())
    }
    
    /// Checks if an object exists
    pub fn object_exists(&self, id: &ObjectID) -> Result<bool> {
        // Check in regular objects
        if self.db.exists(&self.objects_cf, &id.0)? {
            return Ok(true);
        }
        
        // Check in superpositioned objects
        if self.db.exists(&self.superpositioned_objects_cf, &id.0)? {
            return Ok(true);
        }
        
        // Check in deleted objects
        if self.db.exists(&self.deleted_objects_cf, &id.0)? {
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Counts the number of objects in the store
    pub fn count_objects(&self) -> Result<usize> {
        let mut count = 0;
        
        // Count regular objects
        let iter = self.db.iterator(&self.objects_cf)?;
        for _ in iter {
            count += 1;
        }
        
        // Count superpositioned objects
        let iter = self.db.iterator(&self.superpositioned_objects_cf)?;
        for _ in iter {
            count += 1;
        }
        
        Ok(count)
    }
    
    /// Prunes orphaned objects
    pub async fn prune_orphaned_objects(&self) -> Result<usize> {
        // In a real implementation, this would identify and remove objects
        // that are no longer referenced by any active state or transaction
        
        // For now, we'll just return 0 to indicate no objects were pruned
        Ok(0)
    }
    
    /// Checks the integrity of the object store
    pub async fn check_integrity(&self) -> Result<bool> {
        // In a production implementation, this would perform thorough checks
        // such as validating that all indexed objects exist, all objects have
        // proper references, etc.
        
        // For now, we'll perform some basic checks
        
        // Check that we can iterate over all column families
        let mut object_count = 0;
        let iter = self.db.iterator(&self.objects_cf)?;
        for _ in iter {
            object_count += 1;
        }
        
        let iter = self.db.iterator(&self.superpositioned_objects_cf)?;
        for _ in iter {
            object_count += 1;
        }
        
        let iter = self.db.iterator(&self.deleted_objects_cf)?;
        for _ in iter {
            object_count += 1;
        }
        
        // Check a few random objects if there are any
        if object_count > 0 {
            // Get first object from regular objects
            let iter = self.db.iterator(&self.objects_cf)?;
            for (key, _) in iter.take(1) {
                let id = ObjectID(key);
                if let Some(object) = self.get_object(&id)? {
                    // Check that object ID matches key
                    if object.id().0 != id.0 {
                        return Ok(false);
                    }
                } else {
                    // Object should exist
                    return Ok(false);
                }
                break;
            }
        }
        
        Ok(true)
    }
    
    /// Gets an object snapshot at a specific block height
    pub fn get_object_at_height(&self, id: &ObjectID, height: u64) -> Result<Option<Object>> {
        // In a real implementation, this would use a versioned state database
        // to retrieve the object state at a specific block height
        
        // For now, we'll just return the current object
        self.get_object(id)
    }
    
    /// Batch save multiple objects in a single transaction
    pub fn batch_save_objects(&self, objects: &[Object], tx_hash: Option<Vec<u8>>) -> Result<()> {
        // Create a transaction
        let mut txn = self.db.transaction();
        
        for object in objects {
            // Serialize the object
            let object_bytes = bincode::serialize(object)
                .map_err(|e| AevorError::serialization(format!("Failed to serialize object: {}", e)))?;
            
            // Determine which column family to use based on status
            let cf = if object.status() == ObjectStatus::Superposition {
                &self.superpositioned_objects_cf
            } else if object.status() == ObjectStatus::Deleted {
                &self.deleted_objects_cf
            } else {
                &self.objects_cf
            };
            
            // Store the object
            txn.put(cf, &object.id().0, &object_bytes)?;
            
            // Index by owner
            let owner_key = create_owner_key(&object.owner(), object.id());
            txn.put(&self.objects_by_owner_cf, &owner_key, &object.id().0)?;
            
            // Index by type
            let type_key = create_type_key(&format!("{:?}", object.object_type()), object.id());
            txn.put(&self.objects_by_type_cf, &type_key, &object.id().0)?;
            
            // Index by transaction if provided
            if let Some(ref hash) = tx_hash {
                let tx_key = create_tx_key(hash, object.id());
                txn.put(&self.objects_by_tx_cf, &tx_key, &object.id().0)?;
            }
        }
        
        // Execute the transaction
        self.db.execute_transaction(txn)?;
        
        Ok(())
    }
    
    /// Gets objects modified after a specific timestamp
    pub fn get_objects_after_timestamp(&self, timestamp: u64) -> Result<Vec<Object>> {
        let mut result = Vec::new();
        
        // Iterate over all objects
        // Note: In a production system, we'd use a timestamp index
        let iter = self.db.iterator(&self.objects_cf)?;
        for (_, value) in iter {
            if let Ok(Some(object)) = deserialize_object(&value) {
                if object.updated_at() > timestamp {
                    result.push(object);
                }
            }
        }
        
        // Also check superpositioned objects
        let iter = self.db.iterator(&self.superpositioned_objects_cf)?;
        for (_, value) in iter {
            if let Ok(Some(object)) = deserialize_object(&value) {
                if object.updated_at() > timestamp {
                    result.push(object);
                }
            }
        }
        
        Ok(result)
    }
    
    /// Gets objects by multiple criteria in a single query
    pub fn query_objects(&self, criteria: ObjectQueryCriteria) -> Result<Vec<Object>> {
        let mut result = Vec::new();
        
        // Start with the most restrictive criteria
        let candidates: Vec<Object> = if let Some(owner) = &criteria.owner {
            // Get all objects for this owner
            self.get_objects_by_owner(owner)?
        } else if let Some(object_type) = &criteria.object_type {
            // Get all objects of this type
            self.get_objects_by_type(object_type)?
        } else if let Some(tx_hash) = &criteria.tx_hash {
            // Get all objects for this transaction
            self.get_objects_by_transaction(tx_hash)?
        } else {
            // No specific criteria, get all objects
            let mut all_objects = Vec::new();
            
            // Get regular objects
            let iter = self.db.iterator(&self.objects_cf)?;
            for (_, value) in iter {
                if let Ok(Some(object)) = deserialize_object(&value) {
                    all_objects.push(object);
                }
            }
            
            // Get superpositioned objects if requested
            if criteria.include_superpositioned {
                let iter = self.db.iterator(&self.superpositioned_objects_cf)?;
                for (_, value) in iter {
                    if let Ok(Some(object)) = deserialize_object(&value) {
                        all_objects.push(object);
                    }
                }
            }
            
            // Get deleted objects if requested
            if criteria.include_deleted {
                let iter = self.db.iterator(&self.deleted_objects_cf)?;
                for (_, value) in iter {
                    if let Ok(Some(object)) = deserialize_object(&value) {
                        all_objects.push(object);
                    }
                }
            }
            
            all_objects
        };
        
        // Apply additional filters
        for object in candidates {
            // Check owner if specified and not already filtered
            if let Some(owner) = &criteria.owner {
                if object.owner() != owner {
                    continue;
                }
            }
            
            // Check type if specified and not already filtered
            if let Some(object_type) = &criteria.object_type {
                if format!("{:?}", object.object_type()) != *object_type {
                    continue;
                }
            }
            
            // Check status if specified
            if let Some(status) = criteria.status {
                if object.status() != status {
                    continue;
                }
            }
            
            // Check timestamp range if specified
            if let Some(min_timestamp) = criteria.min_timestamp {
                if object.created_at() < min_timestamp {
                    continue;
                }
            }
            
            if let Some(max_timestamp) = criteria.max_timestamp {
                if object.created_at() > max_timestamp {
                    continue;
                }
            }
            
            // Object passed all filters
            result.push(object);
        }
        
        // Apply limit if specified
        if let Some(limit) = criteria.limit {
            result.truncate(limit);
        }
        
        Ok(result)
    }
}

/// Criteria for querying objects
#[derive(Debug, Default)]
pub struct ObjectQueryCriteria {
    /// Filter by owner
    pub owner: Option<Vec<u8>>,
    
    /// Filter by object type
    pub object_type: Option<String>,
    
    /// Filter by transaction hash
    pub tx_hash: Option<Vec<u8>>,
    
    /// Filter by object status
    pub status: Option<ObjectStatus>,
    
    /// Minimum creation timestamp
    pub min_timestamp: Option<u64>,
    
    /// Maximum creation timestamp
    pub max_timestamp: Option<u64>,
    
    /// Include superpositioned objects
    pub include_superpositioned: bool,
    
    /// Include deleted objects
    pub include_deleted: bool,
    
    /// Limit the number of results
    pub limit: Option<usize>,
}

/// Helper to create an owner index key
fn create_owner_key(owner: &[u8], id: &ObjectID) -> Vec<u8> {
    let mut key = owner.to_vec();
    key.extend_from_slice(&[0]); // Separator
    key.extend_from_slice(&id.0);
    key
}

/// Helper to create a type index key
fn create_type_key(object_type: &str, id: &ObjectID) -> Vec<u8> {
    let mut key = object_type.as_bytes().to_vec();
    key.extend_from_slice(&[0]); // Separator
    key.extend_from_slice(&id.0);
    key
}

/// Helper to create a transaction index key
fn create_tx_key(tx_hash: &[u8], id: &ObjectID) -> Vec<u8> {
    let mut key = tx_hash.to_vec();
    key.extend_from_slice(&[0]); // Separator
    key.extend_from_slice(&id.0);
    key
}

/// Deserialize an object from bytes
fn deserialize_object(bytes: &[u8]) -> Result<Option<Object>> {
    bincode::deserialize(bytes)
        .map(Some)
        .map_err(|e| AevorError::deserialization(format!("Failed to deserialize object: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::object::{Object, ObjectID, ObjectType};
    use crate::storage::database::{create_database, Database};
    use crate::config::StorageConfig;
    use tempfile::TempDir;
    
    /// Creates a test ObjectStore with in-memory database
    fn create_test_object_store() -> ObjectStore {
        let config = StorageConfig::default();
        let db = create_database("memory", &config).unwrap();
        let db_arc = Arc::new(db);
        let store = ObjectStore::new(db_arc).unwrap();
        
        // Initialize the store
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(store.initialize())
            .unwrap();
        
        store
    }
    
    /// Creates a test object
    fn create_test_object(id: u32, owner: &[u8]) -> Object {
        let mut object = Object::new(owner.to_vec(), ObjectType::Regular);
        
        // For testing, we'll modify the ID to be predictable
        if id > 0 {
            object.set_id(ObjectID(vec![id as u8; 4]));
        }
        
        // Add some test data
        object.set_data(vec![1, 2, 3, 4]);
        object.add_metadata("test".to_string(), vec![5, 6, 7, 8]);
        
        object
    }
    
    #[test]
    fn test_object_store_basic_operations() {
        let store = create_test_object_store();
        
        // Create a test object
        let owner = vec![9, 10, 11, 12];
        let object = create_test_object(1, &owner);
        let object_id = object.id().clone();
        
        // Store the object
        store.put_object(&object, None).unwrap();
        
        // Retrieve the object
        let retrieved = store.get_object(&object_id).unwrap();
        assert!(retrieved.is_some());
        
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id(), &object_id);
        assert_eq!(retrieved.owner(), &owner);
        assert_eq!(retrieved.data(), &vec![1, 2, 3, 4]);
        
        // Check if object exists
        assert!(store.object_exists(&object_id).unwrap());
        
        // Delete the object
        store.delete_object(&object_id).unwrap();
        
        // Retrieval should now get the deleted object
        let retrieved = store.get_object(&object_id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().status(), ObjectStatus::Deleted);
        
        // Purge the object
        store.purge_object(&object_id).unwrap();
        
        // Object should no longer exist
        assert!(!store.object_exists(&object_id).unwrap());
    }
    
    #[test]
    fn test_objects_by_owner() {
        let store = create_test_object_store();
        
        // Create test objects with the same owner
        let owner1 = vec![1, 1, 1, 1];
        let owner2 = vec![2, 2, 2, 2];
        
        let object1 = create_test_object(1, &owner1);
        let object2 = create_test_object(2, &owner1);
        let object3 = create_test_object(3, &owner2);
        
        // Store the objects
        store.put_object(&object1, None).unwrap();
        store.put_object(&object2, None).unwrap();
        store.put_object(&object3, None).unwrap();
        
        // Retrieve objects by owner
        let owner1_objects = store.get_objects_by_owner(&owner1).unwrap();
        assert_eq!(owner1_objects.len(), 2);
        
        let owner2_objects = store.get_objects_by_owner(&owner2).unwrap();
        assert_eq!(owner2_objects.len(), 1);
    }
    
    #[test]
    fn test_superpositioned_objects() {
        let store = create_test_object_store();
        
        // Create a test object
        let owner = vec![1, 2, 3, 4];
        let mut object = create_test_object(1, &owner);
        let object_id = object.id().clone();
        
        // Make it superpositioned
        object.set_status(ObjectStatus::Superposition);
        
        // Store the object
        store.put_object(&object, None).unwrap();
        
        // Retrieve superpositioned objects
        let superpositioned = store.get_all_superpositioned_objects().unwrap();
        assert_eq!(superpositioned.len(), 1);
        assert_eq!(superpositioned[0].id(), &object_id);
        
        // Create a final state for the object
        let mut final_object = object.clone();
        final_object.set_status(ObjectStatus::Active);
        final_object.set_data(vec![9, 10, 11, 12]);
        
        // Collapse the superposition
        store.collapse_superposition(&object_id, &final_object).unwrap();
        
        // Superpositioned objects should now be empty
        let superpositioned = store.get_all_superpositioned_objects().unwrap();
        assert_eq!(superpositioned.len(), 0);
        
        // Retrieve the object - it should be the final state
        let retrieved = store.get_object(&object_id).unwrap().unwrap();
        assert_eq!(retrieved.status(), ObjectStatus::Active);
        assert_eq!(retrieved.data(), &vec![9, 10, 11, 12]);
    }
}
