use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::hash::{Hash as CryptoHash, HashAlgorithm, Hashable};
use crate::error::{AevorError, Result};

mod state;
mod version;
mod superposition;

pub use state::ObjectState;
pub use version::ObjectVersion;
pub use superposition::{SuperpositionedState, StateCandidate};

/// Unique identifier for objects in the Aevor blockchain
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectID(pub Vec<u8>);

/// Status of an object in the blockchain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectStatus {
    /// Object has been created but not fully initialized
    Created,
    
    /// Object is active and available for use
    Active,
    
    /// Object is temporarily frozen and cannot be modified
    Frozen,
    
    /// Object has been deleted (logically, not physically)
    Deleted,
    
    /// Object is in superposition (multiple potential states)
    Superposition,
}

/// Type of object in the blockchain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectType {
    /// Regular data object
    Regular,
    
    /// Smart contract object
    Contract,
    
    /// Package containing modules/contracts
    Package,
    
    /// Fungible token
    Token,
    
    /// Non-fungible token
    NFT,
    
    /// User-defined object type
    Custom(u16),
}

/// Access control for objects
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessControl {
    /// Object can only be read
    ReadOnly,
    
    /// Object can be read and written
    ReadWrite,
    
    /// No access to the object
    None,
}

/// Dependency type between transactions accessing objects
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DependencyType {
    /// Read-after-Write: Transaction B reads an object written by Transaction A
    ReadAfterWrite,
    
    /// Write-after-Write: Transaction B writes an object previously written by Transaction A
    WriteAfterWrite,
    
    /// Write-after-Read: Transaction B writes an object previously read by Transaction A
    WriteAfterRead,
    
    /// None: No dependency between transactions
    None,
}

/// Transaction reference with associated access type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionRef {
    /// Transaction hash
    pub tx_hash: Vec<u8>,
    
    /// Transaction access type (read or write)
    pub access_type: AccessType,
    
    /// Transaction timestamp
    pub timestamp: u64,
}

/// Access type for an object
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessType {
    /// Object is being read
    Read,
    
    /// Object is being written
    Write,
}

/// Core object structure representing state in the Aevor blockchain
///
/// Objects are the primary unit of state in Aevor, and are used to track
/// dependencies between transactions for the micro-DAG structure. Each object
/// maintains its own access history and can exist in multiple potential states
/// (superposition) until dependencies are resolved.
#[derive(Clone, Serialize, Deserialize)]
pub struct Object {
    /// Unique object identifier
    id: ObjectID,
    
    /// Type of the object
    object_type: ObjectType,
    
    /// Current status of the object
    status: ObjectStatus,
    
    /// Owner of the object (account address)
    owner: Vec<u8>,
    
    /// Version information
    version: ObjectVersion,
    
    /// Object data (serialized content)
    data: Vec<u8>,
    
    /// Object metadata (key-value pairs)
    metadata: HashMap<String, Vec<u8>>,
    
    /// References to other objects
    references: Vec<ObjectID>,
    
    /// Object capabilities and permissions
    capabilities: Vec<String>,
    
    /// Privacy level (0 = public, 1 = private)
    privacy_level: u8,
    
    /// Encryption key hint, if encrypted
    encryption_key_hint: Option<Vec<u8>>,
    
    /// Superpositioned states, if in superposition
    superpositioned_states: Option<SuperpositionedState>,
    
    /// Transaction access history (for dependency tracking)
    access_history: Vec<TransactionRef>,
    
    /// Latest confirmed transaction that accessed this object
    latest_confirmed_tx: Option<Vec<u8>>,
    
    /// Security level of the object (0-3)
    /// 0 = Minimal Security
    /// 1 = Basic Security
    /// 2 = Strong Security
    /// 3 = Full Security
    security_level: u8,
    
    /// Object state hash
    state_hash: Option<Vec<u8>>,
    
    /// List of validators that have confirmed this object state
    validator_confirmations: HashMap<Vec<u8>, Vec<u8>>, // validator_id -> signature
    
    /// Creation timestamp
    created_at: u64,
    
    /// Last updated timestamp
    updated_at: u64,
    
    /// Sequence number for conflict resolution
    sequence: u64,
}

impl Object {
    /// Creates a new object with the specified owner and type
    pub fn new(owner: Vec<u8>, object_type: ObjectType) -> Self {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let id = Self::generate_id();
        
        Self {
            id,
            object_type,
            status: ObjectStatus::Created,
            owner,
            version: ObjectVersion::new(),
            data: Vec::new(),
            metadata: HashMap::new(),
            references: Vec::new(),
            capabilities: Vec::new(),
            privacy_level: 0, // Public by default
            encryption_key_hint: None,
            superpositioned_states: None,
            access_history: Vec::new(),
            latest_confirmed_tx: None,
            security_level: 0, // Minimal security by default
            state_hash: None,
            validator_confirmations: HashMap::new(),
            created_at: now,
            updated_at: now,
            sequence: 0,
        }
    }
    
    /// Generates a unique object ID
    pub fn generate_id() -> ObjectID {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        
        // Generate a unique ID based on timestamp and counter
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;
        let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
        
        // Combine timestamp and counter with a random component
        let mut hasher = blake3::Hasher::new();
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&counter.to_le_bytes());
        
        // Add some randomness
        let random_bytes: [u8; 8] = rand::random();
        hasher.update(&random_bytes);
        
        let hash = hasher.finalize();
        ObjectID(hash.as_bytes().to_vec())
    }
    
    /// Gets the object ID
    pub fn id(&self) -> &ObjectID {
        &self.id
    }
    
    /// Sets a new ID for the object (use with caution)
    pub fn set_id(&mut self, id: ObjectID) {
        self.id = id;
    }
    
    /// Gets the object type
    pub fn object_type(&self) -> ObjectType {
        self.object_type
    }
    
    /// Sets the object type
    pub fn set_object_type(&mut self, object_type: ObjectType) {
        self.object_type = object_type;
    }
    
    /// Gets the object status
    pub fn status(&self) -> ObjectStatus {
        self.status
    }
    
    /// Sets the object status
    pub fn set_status(&mut self, status: ObjectStatus) {
        self.status = status;
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
    }
    
    /// Gets the object owner
    pub fn owner(&self) -> &[u8] {
        &self.owner
    }
    
    /// Sets the object owner
    pub fn set_owner(&mut self, owner: Vec<u8>) {
        self.owner = owner;
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
    }
    
    /// Checks if the object is owned by the given account
    pub fn is_owned_by(&self, account: &[u8]) -> bool {
        self.owner == account
    }
    
    /// Gets the object version
    pub fn version(&self) -> &ObjectVersion {
        &self.version
    }
    
    /// Increments the object version
    pub fn increment_version(&mut self, tx_hash: Vec<u8>) {
        self.version.increment(tx_hash);
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
    }
    
    /// Gets the object data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    
    /// Sets the object data
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
        self.state_hash = None; // Invalidate state hash
    }
    
    /// Updates the object data
    pub fn update_data(&mut self, tx_hash: Vec<u8>, data: Vec<u8>) -> Result<()> {
        self.data = data;
        self.increment_version(tx_hash);
        self.state_hash = None; // Invalidate state hash
        Ok(())
    }
    
    /// Gets object metadata
    pub fn metadata(&self) -> &HashMap<String, Vec<u8>> {
        &self.metadata
    }
    
    /// Gets a specific metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&Vec<u8>> {
        self.metadata.get(key)
    }
    
    /// Adds metadata to the object
    pub fn add_metadata(&mut self, key: String, value: Vec<u8>) {
        self.metadata.insert(key, value);
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
        self.state_hash = None; // Invalidate state hash
    }
    
    /// Gets object references
    pub fn references(&self) -> &[ObjectID] {
        &self.references
    }
    
    /// Adds a reference to another object
    pub fn add_reference(&mut self, reference: ObjectID) {
        if !self.references.contains(&reference) {
            self.references.push(reference);
            self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
            self.state_hash = None; // Invalidate state hash
        }
    }
    
    /// Removes a reference to another object
    pub fn remove_reference(&mut self, reference: &ObjectID) {
        self.references.retain(|r| r != reference);
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
        self.state_hash = None; // Invalidate state hash
    }
    
    /// Gets object capabilities
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }
    
    /// Adds a capability to the object
    pub fn add_capability(&mut self, capability: String) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
            self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
            self.state_hash = None; // Invalidate state hash
        }
    }
    
    /// Checks if the object has a specific capability
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }
    
    /// Gets the privacy level
    pub fn privacy_level(&self) -> u8 {
        self.privacy_level
    }
    
    /// Sets the privacy level
    pub fn set_privacy_level(&mut self, level: u8) {
        if level <= 1 {
            self.privacy_level = level;
            self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
        }
    }
    
    /// Gets the encryption key hint
    pub fn encryption_key_hint(&self) -> Option<&Vec<u8>> {
        self.encryption_key_hint.as_ref()
    }
    
    /// Sets the encryption key hint
    pub fn set_encryption_key_hint(&mut self, hint: Option<Vec<u8>>) {
        self.encryption_key_hint = hint;
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
    }
    
    /// Encrypts the object data for privacy
    pub fn encrypt(&mut self, key: &[u8], key_hint: Vec<u8>) -> Result<()> {
        if self.privacy_level == 0 {
            // Only encrypt if the object is currently public
            let encrypted_data = encrypt_data(&self.data, key)
                .map_err(|e| AevorError::crypto("Encryption failed".into(), e.to_string(), None))?;
            
            self.data = encrypted_data;
            self.privacy_level = 1;
            self.encryption_key_hint = Some(key_hint);
            self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
            self.state_hash = None; // Invalidate state hash
        }
        
        Ok(())
    }
    
    /// Decrypts the object data
    pub fn decrypt(&mut self, key: &[u8]) -> Result<()> {
        if self.privacy_level == 1 {
            // Only decrypt if the object is currently private
            let decrypted_data = decrypt_data(&self.data, key)
                .map_err(|e| AevorError::crypto("Decryption failed".into(), e.to_string(), None))?;
            
            self.data = decrypted_data;
            self.privacy_level = 0;
            self.encryption_key_hint = None;
            self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
            self.state_hash = None; // Invalidate state hash
        }
        
        Ok(())
    }
    
    /// Gets the superpositioned states
    pub fn superpositioned_states(&self) -> Option<&SuperpositionedState> {
        self.superpositioned_states.as_ref()
    }
    
    /// Gets a mutable reference to superpositioned states
    pub fn superpositioned_states_mut(&mut self) -> Option<&mut SuperpositionedState> {
        self.superpositioned_states.as_mut()
    }
    
    /// Checks if the object is in superposition
    pub fn is_in_superposition(&self) -> bool {
        self.status == ObjectStatus::Superposition && self.superpositioned_states.is_some()
    }
    
    /// Puts the object into a superposition state
    pub fn enter_superposition(&mut self) -> Result<()> {
        if self.status == ObjectStatus::Superposition {
            return Err(AevorError::object_versioning("Object is already in superposition"));
        }
        
        // Create a superpositioned state with this object as the initial state
        let superpositioned_state = SuperpositionedState::new(self.clone());
        self.superpositioned_states = Some(superpositioned_state);
        self.status = ObjectStatus::Superposition;
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
        
        Ok(())
    }
    
    /// Adds a potential state to the superposition
    pub fn add_potential_state(&mut self, tx_hash: Vec<u8>, state: Object) -> Result<usize> {
        if self.status != ObjectStatus::Superposition {
            return Err(AevorError::object_versioning("Object is not in superposition"));
        }
        
        if let Some(ref mut superpositioned_states) = self.superpositioned_states {
            let index = superpositioned_states.add_state(tx_hash, state);
            self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
            Ok(index)
        } else {
            Err(AevorError::object_versioning("No superpositioned states initialized"))
        }
    }
    
    /// Adds a validator confirmation for a specific potential state
    pub fn add_validator_confirmation(&mut self, state_index: usize, validator_id: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        if self.status != ObjectStatus::Superposition {
            return Err(AevorError::object_versioning("Object is not in superposition"));
        }
        
        if let Some(ref mut superpositioned_states) = self.superpositioned_states {
            superpositioned_states.add_validator_confirmation(state_index, validator_id, signature)?;
            self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
            Ok(())
        } else {
            Err(AevorError::object_versioning("No superpositioned states initialized"))
        }
    }
    
    /// Collapses the superposition to a specific state
    pub fn collapse_superposition(&mut self, state_index: usize) -> Result<()> {
        if self.status != ObjectStatus::Superposition {
            return Err(AevorError::object_versioning("Object is not in superposition"));
        }
        
        if let Some(superpositioned_states) = self.superpositioned_states.take() {
            let (state, tx_hash) = superpositioned_states.collapse(state_index)?;
            
            // Replace this object with the selected state
            *self = state;
            
            // Update the version and status
            self.increment_version(tx_hash);
            self.status = ObjectStatus::Active;
            self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
            self.state_hash = None; // Invalidate state hash
            
            Ok(())
        } else {
            Err(AevorError::object_versioning("No superpositioned states initialized"))
        }
    }
    
    /// Gets the access history
    pub fn access_history(&self) -> &[TransactionRef] {
        &self.access_history
    }
    
    /// Adds a transaction to the access history
    pub fn add_access(&mut self, tx_hash: Vec<u8>, access_type: AccessType) {
        let tx_ref = TransactionRef {
            tx_hash: tx_hash.clone(),
            access_type,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        
        // Add to access history
        self.access_history.push(tx_ref);
        
        // Trim access history if it gets too large
        if self.access_history.len() > 100 {
            self.access_history.remove(0);
        }
        
        // If this is a write access, update the sequence number
        if access_type == AccessType::Write {
            self.sequence += 1;
        }
        
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
    }
    
    /// Gets the latest confirmed transaction
    pub fn latest_confirmed_tx(&self) -> Option<&Vec<u8>> {
        self.latest_confirmed_tx.as_ref()
    }
    
    /// Sets the latest confirmed transaction
    pub fn set_latest_confirmed_tx(&mut self, tx_hash: Vec<u8>) {
        self.latest_confirmed_tx = Some(tx_hash);
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
    }
    
    /// Gets the security level
    pub fn security_level(&self) -> u8 {
        self.security_level
    }
    
    /// Sets the security level
    pub fn set_security_level(&mut self, level: u8) {
        if level <= 3 {
            self.security_level = level;
            self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
        }
    }
    
    /// Computes dependency type between two transactions accessing this object
    pub fn compute_dependency(&self, tx1_hash: &[u8], tx2_hash: &[u8]) -> DependencyType {
        // Find transactions in the access history
        let tx1 = self.access_history.iter().find(|tx| tx.tx_hash == tx1_hash);
        let tx2 = self.access_history.iter().find(|tx| tx.tx_hash == tx2_hash);
        
        match (tx1, tx2) {
            (Some(tx1), Some(tx2)) => {
                // Ensure tx1 came before tx2
                if tx1.timestamp > tx2.timestamp {
                    return self.compute_dependency(tx2_hash, tx1_hash);
                }
                
                match (tx1.access_type, tx2.access_type) {
                    (AccessType::Write, AccessType::Read) => DependencyType::ReadAfterWrite,
                    (AccessType::Write, AccessType::Write) => DependencyType::WriteAfterWrite,
                    (AccessType::Read, AccessType::Write) => DependencyType::WriteAfterRead,
                    (AccessType::Read, AccessType::Read) => DependencyType::None,
                }
            },
            _ => DependencyType::None,
        }
    }
    
    /// Checks for conflicts with another transaction
    pub fn check_conflicts(&self, tx_hash: &[u8], access_type: AccessType) -> bool {
        // Look at recent accesses to detect conflicts
        for tx_ref in self.access_history.iter().rev().take(10) {
            // Skip the transaction itself
            if tx_ref.tx_hash == tx_hash {
                continue;
            }
            
            // Write-Write conflict
            if tx_ref.access_type == AccessType::Write && access_type == AccessType::Write {
                return true;
            }
            
            // Read-Write conflict
            if tx_ref.access_type == AccessType::Read && access_type == AccessType::Write {
                return true;
            }
            
            // Write-Read conflict (uncomment if needed)
            // if tx_ref.access_type == AccessType::Write && access_type == AccessType::Read {
            //     return true;
            // }
        }
        
        false
    }
    
    /// Gets validator confirmations
    pub fn validator_confirmations(&self) -> &HashMap<Vec<u8>, Vec<u8>> {
        &self.validator_confirmations
    }
    
    /// Adds a validator confirmation
    pub fn add_validator_confirmation(&mut self, validator_id: Vec<u8>, signature: Vec<u8>) {
        self.validator_confirmations.insert(validator_id, signature);
        self.updated_at = chrono::Utc::now().timestamp_millis() as u64;
    }
    
    /// Gets the number of validator confirmations
    pub fn confirmation_count(&self) -> usize {
        self.validator_confirmations.len()
    }
    
    /// Checks if the object has been confirmed by a specific validator
    pub fn is_confirmed_by(&self, validator_id: &[u8]) -> bool {
        self.validator_confirmations.contains_key(validator_id)
    }
    
    /// Gets the sequence number
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    
    /// Gets the creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
    
    /// Gets the update timestamp
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }
    
    /// Creates a deep clone of the object
    pub fn deep_clone(&self) -> Self {
        self.clone()
    }
    
    /// Calculates the hash of the object
    pub fn calculate_hash(&self) -> Vec<u8> {
        // If we already have a cached state hash and the object hasn't changed, return it
        if let Some(ref hash) = self.state_hash {
            return hash.clone();
        }
        
        // Otherwise, calculate the hash
        self.hash_with_algorithm(HashAlgorithm::SHA256).value
    }
    
    /// Updates the cached state hash
    pub fn update_state_hash(&mut self) {
        let hash = self.calculate_hash();
        self.state_hash = Some(hash);
    }
    
    /// Checks if the object is in a valid state
    pub fn is_valid(&self) -> bool {
        // Basic validity checks
        if self.id.0.is_empty() {
            return false;
        }
        
        // Check object status consistency
        if self.status == ObjectStatus::Superposition && self.superpositioned_states.is_none() {
            return false;
        }
        
        // Check privacy level consistency
        if self.privacy_level > 1 {
            return false;
        }
        
        // Check security level consistency
        if self.security_level > 3 {
            return false;
        }
        
        true
    }
}

impl Hashable for Object {
    fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> CryptoHash {
        let mut hasher = CryptoHash::new_hasher(algorithm);
        
        // Hash all fields except those that don't affect the object's state
        hasher.update(&self.id.0);
        hasher.update(&(self.object_type as u8).to_le_bytes());
        hasher.update(&(self.status as u8).to_le_bytes());
        hasher.update(&self.owner);
        hasher.update(&self.version.to_bytes());
        hasher.update(&self.data);
        
        // Hash metadata
        let mut metadata_keys: Vec<&String> = self.metadata.keys().collect();
        metadata_keys.sort(); // Sort for deterministic hashing
        for key in metadata_keys {
            hasher.update(key.as_bytes());
            hasher.update(self.metadata.get(key).unwrap());
        }
        
        // Hash references
        for reference in &self.references {
            hasher.update(&reference.0);
        }
        
        // Hash capabilities
        for capability in &self.capabilities {
            hasher.update(capability.as_bytes());
        }
        
        hasher.update(&[self.privacy_level]);
        
        if let Some(ref hint) = self.encryption_key_hint {
            hasher.update(hint);
        }
        
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&self.created_at.to_le_bytes());
        
        // Finalize the hash
        CryptoHash::new(algorithm, hasher.finalize())
    }
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Object")
            .field("id", &hex::encode(&self.id.0))
            .field("object_type", &self.object_type)
            .field("status", &self.status)
            .field("owner", &hex::encode(&self.owner))
            .field("version", &self.version)
            .field("data_size", &self.data.len())
            .field("metadata_count", &self.metadata.len())
            .field("references_count", &self.references.len())
            .field("capabilities_count", &self.capabilities.len())
            .field("privacy_level", &self.privacy_level)
            .field("in_superposition", &self.is_in_superposition())
            .field("access_history_count", &self.access_history.len())
            .field("security_level", &self.security_level)
            .field("confirmation_count", &self.confirmation_count())
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl fmt::Display for ObjectID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl fmt::Debug for ObjectID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectID({})", hex::encode(&self.0))
    }
}

/// Helper function to encrypt data
fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // In a real implementation, this would use a proper encryption algorithm
    // This is a placeholder that should be replaced with actual encryption
    
    // For now, we'll just XOR the data with the key (not secure, just for demonstration)
    let mut result = Vec::with_capacity(data.len());
    for (i, &byte) in data.iter().enumerate() {
        result.push(byte ^ key[i % key.len()]);
    }
    
    Ok(result)
}

/// Helper function to decrypt data
fn decrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // XOR encryption/decryption is symmetric, so we can use the same function
    encrypt_data(data, key)
}

/// Builder for creating objects
#[derive(Default)]
pub struct ObjectBuilder {
    owner: Option<Vec<u8>>,
    object_type: Option<ObjectType>,
    data: Option<Vec<u8>>,
    metadata: HashMap<String, Vec<u8>>,
    references: Vec<ObjectID>,
    capabilities: Vec<String>,
    privacy_level: u8,
}

impl ObjectBuilder {
    /// Creates a new object builder
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Sets the owner
    pub fn owner(mut self, owner: Vec<u8>) -> Self {
        self.owner = Some(owner);
        self
    }
    
    /// Sets the object type
    pub fn object_type(mut self, object_type: ObjectType) -> Self {
        self.object_type = Some(object_type);
        self
    }
    
    /// Sets the data
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }
    
    /// Adds metadata
    pub fn metadata(mut self, key: String, value: Vec<u8>) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Adds a reference
    pub fn reference(mut self, reference: ObjectID) -> Self {
        self.references.push(reference);
        self
    }
    
    /// Adds a capability
    pub fn capability(mut self, capability: String) -> Self {
        self.capabilities.push(capability);
        self
    }
    
    /// Sets the privacy level
    pub fn privacy_level(mut self, level: u8) -> Self {
        self.privacy_level = level;
        self
    }
    
    /// Builds the object
    pub fn build(self) -> Result<Object> {
        let owner = self.owner.ok_or_else(|| AevorError::object_versioning("Owner is required"))?;
        let object_type = self.object_type.unwrap_or(ObjectType::Regular);
        
        let mut object = Object::new(owner, object_type);
        
        if let Some(data) = self.data {
            object.set_data(data);
        }
        
        for (key, value) in self.metadata {
            object.add_metadata(key, value);
        }
        
        for reference in self.references {
            object.add_reference(reference);
        }
        
        for capability in self.capabilities {
            object.add_capability(capability);
        }
        
        object.set_privacy_level(self.privacy_level);
        
        // Activate the object
        object.set_status(ObjectStatus::Active);
        
        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_object_creation() {
        let owner = vec![1, 2, 3, 4];
        let object = Object::new(owner.clone(), ObjectType::Regular);
        
        assert_eq!(object.status(), ObjectStatus::Created);
        assert_eq!(object.owner(), &owner);
        assert_eq!(object.object_type(), ObjectType::Regular);
        assert_eq!(object.privacy_level(), 0); // Public by default
        assert_eq!(object.security_level(), 0); // Minimal security by default
        assert!(object.is_valid());
    }
    
    #[test]
    fn test_object_builder() {
        let owner = vec![1, 2, 3, 4];
        let data = vec![5, 6, 7, 8];
        
        let object = ObjectBuilder::new()
            .owner(owner.clone())
            .object_type(ObjectType::Token)
            .data(data.clone())
            .metadata("name".to_string(), b"Test Token".to_vec())
            .capability("transfer".to_string())
            .build()
            .unwrap();
        
        assert_eq!(object.status(), ObjectStatus::Active);
        assert_eq!(object.owner(), &owner);
        assert_eq!(object.object_type(), ObjectType::Token);
        assert_eq!(object.data(), &data);
        assert!(object.has_capability("transfer"));
        assert_eq!(object.get_metadata("name").unwrap(), &b"Test Token".to_vec());
    }
    
    #[test]
    fn test_object_versioning() {
        let mut object = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        let tx_hash = vec![10, 11, 12, 13];
        
        assert_eq!(object.version().number(), 0);
        
        object.increment_version(tx_hash.clone());
        assert_eq!(object.version().number(), 1);
        assert_eq!(object.version().created_by(), &tx_hash);
    }
    
    #[test]
    fn test_object_dependencies() {
        let mut object = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        
        let tx1_hash = vec![1, 1, 1, 1];
        let tx2_hash = vec![2, 2, 2, 2];
        
        // Add read access for tx1
        object.add_access(tx1_hash.clone(), AccessType::Read);
        
        // Add write access for tx2
        object.add_access(tx2_hash.clone(), AccessType::Write);
        
        // Check dependencies
        let dep_type = object.compute_dependency(&tx1_hash, &tx2_hash);
        assert_eq!(dep_type, DependencyType::WriteAfterRead);
        
        let dep_type = object.compute_dependency(&tx2_hash, &tx1_hash);
        assert_eq!(dep_type, DependencyType::WriteAfterRead);
    }
    
    #[test]
    fn test_object_superposition() {
        let mut object = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        object.set_data(vec![0, 0, 0, 0]);
        
        // Enter superposition
        assert!(object.enter_superposition().is_ok());
        assert_eq!(object.status(), ObjectStatus::Superposition);
        assert!(object.is_in_superposition());
        
        // Create two potential states
        let mut state1 = object.deep_clone();
        state1.set_data(vec![1, 1, 1, 1]);
        
        let mut state2 = object.deep_clone();
        state2.set_data(vec![2, 2, 2, 2]);
        
        // Add potential states
        let tx1_hash = vec![1, 1, 1, 1];
        let tx2_hash = vec![2, 2, 2, 2];
        
        let idx1 = object.add_potential_state(tx1_hash.clone(), state1).unwrap();
        let idx2 = object.add_potential_state(tx2_hash.clone(), state2).unwrap();
        
        assert_eq!(idx1, 1); // 0 is the original state
        assert_eq!(idx2, 2);
        
        // Add validator confirmations
        let validator1 = vec![10, 10, 10, 10];
        let validator2 = vec![20, 20, 20, 20];
        
        assert!(object.add_validator_confirmation(idx1, validator1.clone(), vec![1]).is_ok());
        assert!(object.add_validator_confirmation(idx1, validator2.clone(), vec![2]).is_ok());
        
        // Collapse to state 1
        assert!(object.collapse_superposition(idx1).is_ok());
        assert_eq!(object.status(), ObjectStatus::Active);
        assert_eq!(object.data(), &vec![1, 1, 1, 1]);
    }
    
    #[test]
    fn test_object_hashing() {
        let mut object = Object::new(vec![1, 2, 3, 4], ObjectType::Regular);
        let hash1 = object.calculate_hash();
        
        // Modify the object
        object.set_data(vec![5, 6, 7, 8]);
        let hash2 = object.calculate_hash();
        
        // Hashes should be different
        assert_ne!(hash1, hash2);
        
        // Cache the hash
        object.update_state_hash();
        
        // Getting the hash again should return the cached value
        let hash3 = object.calculate_hash();
        assert_eq!(hash2, hash3);
    }
}
