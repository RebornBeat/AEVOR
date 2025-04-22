use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::core::{Object, ObjectID, Transaction};
use crate::core::object::{AccessControl, ObjectStatus};
use crate::error::{AevorError, Result};

/// Unique identifier for execution contexts
pub type ContextID = String;

/// Resource limits for execution
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum memory usage in bytes
    pub max_memory_bytes: usize,

    /// Maximum computation time in milliseconds
    pub max_time_ms: u64,

    /// Maximum storage usage in bytes
    pub max_storage_bytes: usize,

    /// Maximum number of instructions
    pub max_instructions: u64,

    /// Maximum number of objects that can be created
    pub max_objects_created: usize,

    /// Maximum number of objects that can be modified
    pub max_objects_modified: usize,
}

/// Resource usage tracking
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Memory usage in bytes
    pub memory_bytes: usize,

    /// Storage usage in bytes
    pub storage_bytes: usize,

    /// Number of instructions executed
    pub instructions: u64,

    /// Number of objects created
    pub objects_created: usize,

    /// Number of objects modified
    pub objects_modified: usize,

    /// Execution time in milliseconds
    pub execution_time_ms: u64,

    /// Modified objects
    pub modified_objects: Vec<ObjectID>,

    /// Created objects
    pub created_objects: Vec<ObjectID>,

    /// Deleted objects
    pub deleted_objects: Vec<ObjectID>,

    /// Logs generated during execution
    pub logs: Vec<String>,
}

/// Snapshot of an execution context state
#[derive(Debug, Clone)]
pub struct ContextSnapshot {
    /// Snapshot ID
    pub id: String,

    /// Context ID this snapshot is from
    pub context_id: ContextID,

    /// Objects in the context at the time of snapshot
    pub objects: HashMap<ObjectID, Object>,

    /// Resource usage at the time of snapshot
    pub resource_usage: ResourceUsage,

    /// Access control at the time of snapshot
    pub access_control: HashMap<ObjectID, AccessControl>,

    /// Timestamp when the snapshot was taken
    pub timestamp: u64,
}

/// Execution context for smart contracts and transactions
///
/// The execution context manages all resources accessed during execution,
/// including objects, memory, and CPU time. It provides isolation between
/// different executions and tracks resource usage to enforce limits.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Unique identifier for the context
    id: ContextID,

    /// Objects accessible in the context
    objects: HashMap<ObjectID, Object>,

    /// Original objects (before modifications)
    original_objects: HashMap<ObjectID, Object>,

    /// Current transaction being executed
    transaction: Option<Transaction>,

    /// Resource limits
    limits: ResourceLimits,

    /// Execution start time
    start_time: Option<Instant>,

    /// Resource usage
    resource_usage: ResourceUsage,

    /// Access control for objects
    access_control: HashMap<ObjectID, AccessControl>,

    /// Environment variables
    env_vars: HashMap<String, String>,

    /// Random seed for deterministic randomness
    random_seed: [u8; 32],

    /// Snapshots of the context at various points
    snapshots: Vec<ContextSnapshot>,

    /// Parent context ID if this is a child context
    parent_context_id: Option<ContextID>,

    /// Privacy level (0 = public, 1 = private)
    privacy_level: u8,

    /// Whether the context is in a TEE environment
    is_tee: bool,

    /// Whether the context is in validation mode
    is_validation_mode: bool,
}

impl ExecutionContext {
    /// Creates a new execution context
    pub fn new() -> Self {
        let id = format!("ctx-{}", Uuid::new_v4());

        Self {
            id,
            objects: HashMap::new(),
            original_objects: HashMap::new(),
            transaction: None,
            limits: ResourceLimits {
                max_memory_bytes: 100 * 1024 * 1024, // 100 MB
                max_time_ms: 5000,                  // 5 seconds
                max_storage_bytes: 10 * 1024 * 1024, // 10 MB
                max_instructions: 10_000_000,       // 10 million instructions
                max_objects_created: 100,           // 100 objects
                max_objects_modified: 100,          // 100 objects
            },
            start_time: None,
            resource_usage: ResourceUsage::default(),
            access_control: HashMap::new(),
            env_vars: HashMap::new(),
            random_seed: [0; 32],
            snapshots: Vec::new(),
            parent_context_id: None,
            privacy_level: 0,
            is_tee: false,
            is_validation_mode: false,
        }
    }

    /// Creates an execution context for a transaction
    pub fn for_transaction(transaction: &Transaction) -> Result<Self> {
        let mut context = Self::new();
        context.transaction = Some(transaction.clone());

        // Set transaction-specific parameters
        context.random_seed = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&transaction.hash());
            let mut seed = [0u8; 32];
            seed.copy_from_slice(hasher.finalize().as_bytes());
            seed
        };

        // Set privacy level based on transaction
        context.privacy_level = transaction.privacy_level();

        Ok(context)
    }

    /// Gets the context ID
    pub fn id(&self) -> &ContextID {
        &self.id
    }

    /// Gets the current transaction
    pub fn transaction(&self) -> Option<&Transaction> {
        self.transaction.as_ref()
    }

    /// Set resource limits
    pub fn set_limits(&mut self, gas_limit: u64, memory_limit: usize, time_limit_ms: u64) {
        self.limits.max_memory_bytes = memory_limit;
        self.limits.max_time_ms = time_limit_ms;

        // Derive other limits from gas limit
        self.limits.max_instructions = gas_limit;
        self.limits.max_storage_bytes = (gas_limit / 10) as usize;
        self.limits.max_objects_created = (gas_limit / 10000) as usize;
        self.limits.max_objects_modified = (gas_limit / 5000) as usize;
    }

    /// Sets the validation mode
    pub fn set_validation_mode(&mut self, is_validation_mode: bool) {
        self.is_validation_mode = is_validation_mode;
    }

    /// Gets the resource limits
    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Gets the resource usage
    pub fn resource_usage(&self) -> &ResourceUsage {
        &self.resource_usage
    }

    /// Starts execution timing
    pub fn start_execution(&mut self) -> Instant {
        let now = Instant::now();
        self.start_time = Some(now);
        now
    }

    /// Stops execution and returns elapsed time in milliseconds
    pub fn stop_execution(&mut self) -> u64 {
        if let Some(start) = self.start_time {
            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_millis() as u64;
            self.resource_usage.execution_time_ms = elapsed_ms;
            self.start_time = None;
            elapsed_ms
        } else {
            0
        }
    }

    /// Checks if the time limit is exceeded
    pub fn is_time_limit_exceeded(&self) -> bool {
        if let Some(start) = self.start_time {
            let elapsed_ms = start.elapsed().as_millis() as u64;
            elapsed_ms > self.limits.max_time_ms
        } else {
            false
        }
    }

    /// Tracks memory allocation
    pub fn track_memory(&mut self, bytes: usize) -> Result<()> {
        let new_memory = self.resource_usage.memory_bytes.saturating_add(bytes);

        // Check limit
        if new_memory > self.limits.max_memory_bytes {
            return Err(AevorError::execution(format!(
                "Memory limit exceeded: {} > {}",
                new_memory,
                self.limits.max_memory_bytes
            )));
        }

        self.resource_usage.memory_bytes = new_memory;
        Ok(())
    }

    /// Tracks storage allocation
    pub fn track_storage(&mut self, bytes: usize) -> Result<()> {
        let new_storage = self.resource_usage.storage_bytes.saturating_add(bytes);

        // Check limit
        if new_storage > self.limits.max_storage_bytes {
            return Err(AevorError::execution(format!(
                "Storage limit exceeded: {} > {}",
                new_storage,
                self.limits.max_storage_bytes
            )));
        }

        self.resource_usage.storage_bytes = new_storage;
        Ok(())
    }

    /// Tracks instruction execution
    pub fn track_instructions(&mut self, count: u64) -> Result<()> {
        let new_instructions = self.resource_usage.instructions.saturating_add(count);

        // Check limit
        if new_instructions > self.limits.max_instructions {
            return Err(AevorError::execution(format!(
                "Instruction limit exceeded: {} > {}",
                new_instructions,
                self.limits.max_instructions
            )));
        }

        self.resource_usage.instructions = new_instructions;
        Ok(())
    }

    /// Tracks object creation
    pub fn track_object_creation(&mut self, object_id: &ObjectID) -> Result<()> {
        let new_count = self.resource_usage.objects_created.saturating_add(1);

        // Check limit
        if new_count > self.limits.max_objects_created {
            return Err(AevorError::execution(format!(
                "Object creation limit exceeded: {} > {}",
                new_count,
                self.limits.max_objects_created
            )));
        }

        self.resource_usage.objects_created = new_count;
        self.resource_usage.created_objects.push(object_id.clone());
        Ok(())
    }

    /// Tracks object modification
    pub fn track_object_modification(&mut self, object_id: &ObjectID) -> Result<()> {
        let new_count = self.resource_usage.objects_modified.saturating_add(1);

        // Check limit
        if new_count > self.limits.max_objects_modified {
            return Err(AevorError::execution(format!(
                "Object modification limit exceeded: {} > {}",
                new_count,
                self.limits.max_objects_modified
            )));
        }

        self.resource_usage.objects_modified = new_count;

        // Only add to modified objects if not already in created objects
        if !self.resource_usage.created_objects.contains(object_id) && 
           !self.resource_usage.modified_objects.contains(object_id) {
            self.resource_usage.modified_objects.push(object_id.clone());
        }

        Ok(())
    }

    /// Tracks object deletion
    pub fn track_object_deletion(&mut self, object_id: &ObjectID) -> Result<()> {
        // Add to deleted objects if not already there
        if !self.resource_usage.deleted_objects.contains(object_id) {
            self.resource_usage.deleted_objects.push(object_id.clone());
        }

        Ok(())
    }

    /// Adds a log entry
    pub fn add_log(&mut self, log: String) {
        self.resource_usage.logs.push(log);
    }

    /// Gets an object by ID
    pub fn get_object(&self, id: &ObjectID) -> Result<Object> {
        self.objects.get(id)
            .cloned()
            .ok_or_else(|| AevorError::execution(format!("Object not found: {:?}", id)))
    }

    /// Gets the original (unmodified) object by ID
    pub fn get_original_object(&self, id: &ObjectID) -> Result<&Object> {
        self.original_objects.get(id)
            .ok_or_else(|| AevorError::execution(format!("Original object not found: {:?}", id)))
    }

    /// Gets all objects in the context
    pub fn get_all_objects(&self) -> &HashMap<ObjectID, Object> {
        &self.objects
    }

    /// Gets a mutable reference to an object
    pub fn get_object_mut(&mut self, id: &ObjectID) -> Result<&mut Object> {
        self.check_object_access(id, AccessControl::ReadWrite)?;

        self.objects.get_mut(id)
            .ok_or_else(|| AevorError::execution(format!("Object not found: {:?}", id)))
    }

    /// Loads an object into the context
    pub fn load_object(&mut self, object: Object) -> Result<()> {
        let id = object.id().clone();
        let size = bincode::serialize(&object)?.len();

        // Track storage
        self.track_storage(size)?;

        // Store the original object
        if !self.original_objects.contains_key(&id) {
            self.original_objects.insert(id.clone(), object.clone());
        }

        // Store the object
        self.objects.insert(id.clone(), object);

        // Set default access control
        self.access_control.insert(id, AccessControl::ReadOnly);

        Ok(())
    }

    /// Updates an existing object
    pub fn update_object(&mut self, object: Object) -> Result<()> {
        let id = object.id().clone();

        // Check if object exists
        if !self.objects.contains_key(&id) {
            return Err(AevorError::execution(format!("Object not found for update: {:?}", id)));
        }

        // Check access control
        self.check_object_access(&id, AccessControl::ReadWrite)?;

        // Track modification
        self.track_object_modification(&id)?;

        // Update object
        self.objects.insert(id, object);

        Ok(())
    }

    /// Creates a new object in the context
    pub fn create_object(&mut self, object: Object) -> Result<()> {
        let id = object.id().clone();
        let size = bincode::serialize(&object)?.len();

        // Track storage and creation
        self.track_storage(size)?;
        self.track_object_creation(&id)?;

        // Store the object
        self.objects.insert(id.clone(), object);

        // Set access control
        self.access_control.insert(id, AccessControl::ReadWrite);

        Ok(())
    }

    /// Deletes an object from the context
    pub fn delete_object(&mut self, id: &ObjectID) -> Result<()> {
        // Check if object exists
        if !self.objects.contains_key(id) {
            return Err(AevorError::execution(format!("Object not found for deletion: {:?}", id)));
        }

        // Check access control
        self.check_object_access(id, AccessControl::ReadWrite)?;

        // Track deletion
        self.track_object_deletion(id)?;

        // Remove object
        self.objects.remove(id);
        self.access_control.remove(id);

        Ok(())
    }

    /// Gets or creates an object in the context
    pub fn get_or_create_object(&mut self, id: &ObjectID, creator: impl FnOnce() -> Object) -> Result<Object> {
        if self.objects.contains_key(id) {
            self.get_object(id)
        } else {
            let object = creator();
            self.create_object(object.clone())?;
            Ok(object)
        }
    }

    /// Checks if object access is allowed
    pub fn check_object_access(&self, id: &ObjectID, required_access: AccessControl) -> Result<()> {
        // Get current access control
        let current_access = self.access_control.get(id).copied().unwrap_or(AccessControl::None);

        // Check if access is allowed
        match (current_access, requiredaccess) {
            (AccessControl::None, ) => {
                Err(AevorError::execution(format!("No access to object: {:?}", id)))
            }
            (AccessControl::ReadOnly, AccessControl::ReadWrite) => {
                Err(AevorError::execution(format!("Read-only access to object: {:?}", id)))
            }
            _ => Ok(()),
        }
    }

    /// Sets object access control
    pub fn set_object_access(&mut self, id: &ObjectID, access: AccessControl) {
        self.access_control.insert(id.clone(), access);
    }

    /// Creates a snapshot of the current context state
    pub fn create_snapshot(&mut self) -> ContextSnapshot {
        let snapshot_id = format!("snapshot-{}", Uuid::new_v4());
        let timestamp = chrono::Utc::now().timestamp_millis() as u64;

        let snapshot = ContextSnapshot {
            id: snapshot_id,
            context_id: self.id.clone(),
            objects: self.objects.clone(),
            resource_usage: self.resource_usage.clone(),
            access_control: self.access_control.clone(),
            timestamp,
        };

        self.snapshots.push(snapshot.clone());
        snapshot
    }

    /// Restores context from a snapshot
    pub fn restore_from_snapshot(&mut self, snapshot_id: &str) -> Result<()> {
        // Find the snapshot
        let snapshot = self.snapshots.iter()
            .find(|s| s.id == snapshot_id)
            .cloned()
            .ok_or_else(|| AevorError::execution(format!("Snapshot not found: {}", snapshot_id)))?;

        // Restore state
        self.objects = snapshot.objects;
        self.resource_usage = snapshot.resource_usage;
        self.access_control = snapshot.access_control;

        Ok(())
    }

    /// Gets all snapshots
    pub fn get_snapshots(&self) -> &[ContextSnapshot] {
        &self.snapshots
    }

    /// Gets a specific snapshot by ID
    pub fn get_snapshot(&self, snapshot_id: &str) -> Option<&ContextSnapshot> {
        self.snapshots.iter().find(|s| s.id == snapshot_id)
    }

    /// Creates a child context with isolated resources
    pub fn create_child_context(&self) -> Self {
        let id = format!("ctx-{}", Uuid::new_v4());

        let mut child = Self::new();
        child.id = id;
        child.parent_context_id = Some(self.id.clone());
        child.privacy_level = self.privacy_level;
        child.is_tee = self.is_tee;

        // Inherit some settings from parent
        child.limits = self.limits.clone();

        child
    }

    /// Gets the created objects
    pub fn created_objects(&self) -> &[ObjectID] {
        &self.resource_usage.created_objects
    }

    /// Gets the modified objects
    pub fn modified_objects(&self) -> &[ObjectID] {
        &self.resource_usage.modified_objects
    }

    /// Gets the deleted objects
    pub fn deleted_objects(&self) -> &[ObjectID] {
        &self.resource_usage.deleted_objects
    }

    /// Checks if the context is running in TEE
    pub fn is_tee_enabled(&self) -> bool {
        self.is_tee
    }

    /// Sets TEE mode
    pub fn set_tee_mode(&mut self, is_tee: bool) {
        self.is_tee = is_tee;
    }

    /// Gets the privacy level
    pub fn privacy_level(&self) -> u8 {
        self.privacy_level
    }

    /// Sets the privacy level
    pub fn set_privacy_level(&mut self, level: u8) {
        if level <= 1 {
            self.privacy_level = level;
        }
    }

    /// Sets or updates an environment variable
    pub fn set_env_var(&mut self, key: String, value: String) {
        self.env_vars.insert(key, value);
    }

    /// Gets an environment variable
    pub fn get_env_var(&self, key: &str) -> Option<&String> {
        self.env_vars.get(key)
    }

    /// Gets the random seed
    pub fn random_seed(&self) -> &[u8; 32] {
        &self.random_seed
    }

    /// Sets the random seed
    pub fn set_random_seed(&mut self, seed: [u8; 32]) {
        self.random_seed = seed;
    }

    /// Clears all objects from the context
    pub fn clear_objects(&mut self) {
        self.objects.clear();
        self.original_objects.clear();
        self.access_control.clear();
    }

    /// Checks if the context is in validation mode
    pub fn is_validation_mode(&self) -> bool {
        self.is_validation_mode
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}
