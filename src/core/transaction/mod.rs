use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::core::object::{ObjectID, AccessType, DependencyType};
use crate::crypto::hash::{Hash as CryptoHash, HashAlgorithm, Hashable};
use crate::crypto::signature::{Signature, SignatureAlgorithm};
use crate::error::{AevorError, Result};

mod data;
mod dependency;
mod security;
mod types;
mod validation;

pub use data::TransactionData;
pub use dependency::TransactionDependency;
pub use security::SecurityLevel;
pub use types::TransactionType;
pub use validation::ValidationStatus;

/// Status of a transaction execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction is pending execution
    Pending,
    
    /// Transaction execution succeeded
    Success,
    
    /// Transaction execution failed
    Failed,
    
    /// Transaction is in superposition (multiple potential outcomes)
    Superposition,
    
    /// Transaction has timed out
    Timeout,
}

/// Reference to an object accessed by a transaction
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Object ID
    pub id: ObjectID,
    
    /// Access type (read or write)
    pub access_type: AccessType,
}

/// Represents a transaction in the Aevor blockchain
///
/// Transactions are the primary units of execution in Aevor, and are
/// organized in a micro-DAG based on their dependencies. Each transaction
/// explicitly declares its read and write sets to enable efficient
/// parallelism and conflict detection.
#[derive(Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction hash
    #[serde(skip)]
    hash: Option<Vec<u8>>,
    
    /// Address of the transaction sender
    sender: Vec<u8>,
    
    /// Transaction nonce
    nonce: u64,
    
    /// Maximum gas allowed for the transaction
    gas_limit: u64,
    
    /// Price per unit of gas
    gas_price: u64,
    
    /// Type of the transaction
    transaction_type: TransactionType,
    
    /// Transaction-specific data
    data: TransactionData,
    
    /// Transaction signature
    signature: Option<Signature>,
    
    /// Execution status of the transaction
    status: TransactionStatus,
    
    /// Privacy level (0 = public, 1 = private)
    privacy_level: u8,
    
    /// Explicitly declared read set (objects read by this transaction)
    read_set: HashSet<ObjectID>,
    
    /// Explicitly declared write set (objects written by this transaction)
    write_set: HashSet<ObjectID>,
    
    /// Dependencies on other transactions
    dependencies: Vec<TransactionDependency>,
    
    /// Current security level of the transaction
    security_level: SecurityLevel,
    
    /// BLS signature bundle for validation
    #[serde(skip)]
    signature_bundle: Option<Vec<u8>>,
    
    /// Timestamp when the transaction was created
    created_at: u64,
    
    /// Timestamp when the transaction was included in a block
    included_at: Option<u64>,
    
    /// Timestamp when the transaction was executed
    executed_at: Option<u64>,
    
    /// Gas used during execution
    gas_used: Option<u64>,
    
    /// Error message, if any
    error: Option<String>,
    
    /// Validator confirmations
    validator_confirmations: HashMap<Vec<u8>, Vec<u8>>, // validator_id -> signature
    
    /// Chain ID
    chain_id: Vec<u8>,
    
    /// Transaction metadata (arbitrary key-value pairs)
    metadata: HashMap<String, Vec<u8>>,
}

impl Transaction {
    /// Creates a new transaction
    pub fn new(
        sender: Vec<u8>,
        nonce: u64,
        gas_limit: u64,
        gas_price: u64,
        transaction_type: TransactionType,
        data: TransactionData,
        chain_id: Vec<u8>,
    ) -> Self {
        Self {
            hash: None,
            sender,
            nonce,
            gas_limit,
            gas_price,
            transaction_type,
            data,
            signature: None,
            status: TransactionStatus::Pending,
            privacy_level: 0, // Public by default
            read_set: HashSet::new(),
            write_set: HashSet::new(),
            dependencies: Vec::new(),
            security_level: SecurityLevel::Minimal,
            signature_bundle: None,
            created_at: chrono::Utc::now().timestamp_millis() as u64,
            included_at: None,
            executed_at: None,
            gas_used: None,
            error: None,
            validator_confirmations: HashMap::new(),
            chain_id,
            metadata: HashMap::new(),
        }
    }
    
    /// Calculates the hash of the transaction
    pub fn hash(&self) -> Vec<u8> {
        // If we have a cached hash, return it
        if let Some(ref hash) = self.hash {
            return hash.clone();
        }
        
        // Otherwise, calculate the hash
        self.hash_with_algorithm(HashAlgorithm::SHA256).value
    }
    
    /// Updates the cached hash
    pub fn update_hash(&mut self) {
        let hash = self.hash();
        self.hash = Some(hash);
    }
    
    /// Signs the transaction with the sender's private key
    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        // Get the transaction hash
        let hash = self.hash();
        
        // Sign the hash
        let signature = Signature::sign(SignatureAlgorithm::ED25519, private_key, &hash)
            .map_err(|e| AevorError::crypto("Signing failed".into(), e.to_string(), None))?;
        
        self.signature = Some(signature);
        Ok(())
    }
    
    /// Verifies the transaction signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool> {
        // Check if the transaction is signed
        let signature = match &self.signature {
            Some(sig) => sig,
            None => return Ok(false),
        };
        
        // Get the transaction hash
        let hash = self.hash();
        
        // Verify the signature
        signature.verify(public_key, &hash)
            .map_err(|e| AevorError::crypto("Signature verification failed".into(), e.to_string(), None))
    }
    
    /// Gets the sender address
    pub fn sender(&self) -> &[u8] {
        &self.sender
    }
    
    /// Gets the transaction nonce
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
    
    /// Gets the gas limit
    pub fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
    
    /// Gets the gas price
    pub fn gas_price(&self) -> u64 {
        self.gas_price
    }
    
    /// Gets the transaction type
    pub fn transaction_type(&self) -> TransactionType {
        self.transaction_type
    }
    
    /// Gets the transaction data
    pub fn data(&self) -> &TransactionData {
        &self.data
    }
    
    /// Gets a mutable reference to transaction data
    pub fn data_mut(&mut self) -> &mut TransactionData {
        &mut self.data
    }
    
    /// Gets the transaction signature
    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
    
    /// Gets the transaction status
    pub fn status(&self) -> TransactionStatus {
        self.status
    }
    
    /// Sets the transaction status
    pub fn set_status(&mut self, status: TransactionStatus) {
        self.status = status;
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
    
    /// Gets the read set
    pub fn read_set(&self) -> &HashSet<ObjectID> {
        &self.read_set
    }
    
    /// Adds an object to the read set
    pub fn add_read(&mut self, object_id: ObjectID) {
        self.read_set.insert(object_id);
    }
    
    /// Gets the write set
    pub fn write_set(&self) -> &HashSet<ObjectID> {
        &self.write_set
    }
    
    /// Adds an object to the write set
    pub fn add_write(&mut self, object_id: ObjectID) {
        self.write_set.insert(object_id);
    }
    
    /// Gets all objects accessed by this transaction
    pub fn accessed_objects(&self) -> Vec<ObjectRef> {
        let mut result = Vec::new();
        
        // Add read-only objects
        for id in self.read_set.iter() {
            if !self.write_set.contains(id) {
                result.push(ObjectRef {
                    id: id.clone(),
                    access_type: AccessType::Read,
                });
            }
        }
        
        // Add write objects
        for id in self.write_set.iter() {
            result.push(ObjectRef {
                id: id.clone(),
                access_type: AccessType::Write,
            });
        }
        
        result
    }
    
    /// Gets the dependencies
    pub fn dependencies(&self) -> &[TransactionDependency] {
        &self.dependencies
    }
    
    /// Adds a dependency on another transaction
    pub fn add_dependency(&mut self, dependency: TransactionDependency) {
        // Check if we already have this dependency
        if !self.dependencies.iter().any(|d| d == &dependency) {
            self.dependencies.push(dependency);
        }
    }
    
    /// Computes dependency with another transaction
    pub fn compute_dependency(&self, other: &Transaction) -> DependencyType {
        // Check for RAW (Read-After-Write) dependency
        for id in &self.read_set {
            if other.write_set.contains(id) {
                return DependencyType::ReadAfterWrite;
            }
        }
        
        // Check for WAW (Write-After-Write) dependency
        for id in &self.write_set {
            if other.write_set.contains(id) {
                return DependencyType::WriteAfterWrite;
            }
        }
        
        // Check for WAR (Write-After-Read) dependency
        for id in &self.write_set {
            if other.read_set.contains(id) {
                return DependencyType::WriteAfterRead;
            }
        }
        
        // No dependency
        DependencyType::None
    }
    
    /// Gets the security level
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
    
    /// Sets the security level
    pub fn set_security_level(&mut self, level: SecurityLevel) {
        self.security_level = level;
    }
    
    /// Gets the signature bundle
    pub fn signature_bundle(&self) -> Option<&Vec<u8>> {
        self.signature_bundle.as_ref()
    }
    
    /// Sets the signature bundle
    pub fn set_signature_bundle(&mut self, bundle: Vec<u8>) {
        self.signature_bundle = Some(bundle);
    }
    
    /// Gets the created timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
    
    /// Gets the included timestamp
    pub fn included_at(&self) -> Option<u64> {
        self.included_at
    }
    
    /// Sets the included timestamp
    pub fn set_included_at(&mut self, timestamp: u64) {
        self.included_at = Some(timestamp);
    }
    
    /// Gets the executed timestamp
    pub fn executed_at(&self) -> Option<u64> {
        self.executed_at
    }
    
    /// Sets the executed timestamp
    pub fn set_executed_at(&mut self, timestamp: u64) {
        self.executed_at = Some(timestamp);
    }
    
    /// Gets the gas used
    pub fn gas_used(&self) -> Option<u64> {
        self.gas_used
    }
    
    /// Sets the gas used
    pub fn set_gas_used(&mut self, gas: u64) {
        self.gas_used = Some(gas);
    }
    
    /// Gets the error message
    pub fn error(&self) -> Option<&String> {
        self.error.as_ref()
    }
    
    /// Sets the error message
    pub fn set_error(&mut self, error: String) {
        self.error = Some(error);
        self.status = TransactionStatus::Failed;
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
    
    /// Checks if the transaction has been confirmed by a specific validator
    pub fn is_confirmed_by(&self, validator_id: &[u8]) -> bool {
        self.validator_confirmations.contains_key(validator_id)
    }
    
    /// Gets the chain ID
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }
    
    /// Gets the metadata
    pub fn metadata(&self) -> &HashMap<String, Vec<u8>> {
        &self.metadata
    }
    
    /// Gets a specific metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&Vec<u8>> {
        self.metadata.get(key)
    }
    
    /// Adds metadata
    pub fn add_metadata(&mut self, key: String, value: Vec<u8>) {
        self.metadata.insert(key, value);
        self.hash = None; // Invalidate hash cache
    }
    
    /// Validates this transaction's basic properties
    pub fn validate_basic(&self) -> Result<()> {
        // Check sender
        if self.sender.is_empty() {
            return Err(AevorError::validation("Sender address is empty"));
        }
        
        // Check gas limit
        if self.gas_limit == 0 {
            return Err(AevorError::validation("Gas limit is zero"));
        }
        
        // Check gas price
        if self.gas_price == 0 {
            return Err(AevorError::validation("Gas price is zero"));
        }
        
        // Check signature if present
        if let Some(ref sig) = self.signature {
            if sig.value().is_empty() {
                return Err(AevorError::validation("Signature is empty"));
            }
        }
        
        // Check chain ID
        if self.chain_id.is_empty() {
            return Err(AevorError::validation("Chain ID is empty"));
        }
        
        // Check transaction data
        self.data.validate_basic()?;
        
        Ok(())
    }
    
    /// Calculates the transaction cost (gas_limit * gas_price)
    pub fn cost(&self) -> u64 {
        self.gas_limit.saturating_mul(self.gas_price)
    }
    
    /// Checks if the transaction is valid for inclusion in a block
    pub fn is_valid_for_inclusion(&self) -> bool {
        // Basic validation
        if let Err(_) = self.validate_basic() {
            return false;
        }
        
        // Must be signed
        if self.signature.is_none() {
            return false;
        }
        
        // Status checks
        match self.status {
            TransactionStatus::Pending => true,
            _ => false,
        }
    }
    
    /// Clones this transaction without the signature
    pub fn clone_unsigned(&self) -> Self {
        let mut cloned = self.clone();
        cloned.signature = None;
        cloned.hash = None;
        cloned
    }
    
    /// Creates a deep clone of the transaction
    pub fn deep_clone(&self) -> Self {
        self.clone()
    }
}

impl Hashable for Transaction {
    fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> CryptoHash {
        let mut hasher = CryptoHash::new_hasher(algorithm);
        
        // Hash transaction fields excluding signature and execution results
        hasher.update(&self.sender);
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.gas_price.to_le_bytes());
        hasher.update(&(self.transaction_type as u8).to_le_bytes());
        
        // Hash transaction data
        let data_bytes = self.data.to_bytes();
        hasher.update(&data_bytes);
        
        // Hash privacy level
        hasher.update(&[self.privacy_level]);
        
        // Hash read set
        let mut read_set: Vec<&ObjectID> = self.read_set.iter().collect();
        read_set.sort_by(|a, b| a.0.cmp(&b.0)); // Sort for deterministic hashing
        for id in read_set {
            hasher.update(&id.0);
        }
        
        // Hash write set
        let mut write_set: Vec<&ObjectID> = self.write_set.iter().collect();
        write_set.sort_by(|a, b| a.0.cmp(&b.0)); // Sort for deterministic hashing
        for id in write_set {
            hasher.update(&id.0);
        }
        
        // Hash chain ID
        hasher.update(&self.chain_id);
        
        // Finalize the hash
        CryptoHash::new(algorithm, hasher.finalize())
    }
}

impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("hash", &self.hash.as_ref().map(hex::encode).unwrap_or_else(|| hex::encode(self.hash())))
            .field("sender", &hex::encode(&self.sender))
            .field("nonce", &self.nonce)
            .field("gas_limit", &self.gas_limit)
            .field("gas_price", &self.gas_price)
            .field("transaction_type", &self.transaction_type)
            .field("data", &self.data)
            .field("status", &self.status)
            .field("privacy_level", &self.privacy_level)
            .field("read_set", &self.read_set.len())
            .field("write_set", &self.write_set.len())
            .field("dependencies", &self.dependencies.len())
            .field("security_level", &self.security_level)
            .field("created_at", &self.created_at)
            .field("included_at", &self.included_at)
            .field("executed_at", &self.executed_at)
            .field("gas_used", &self.gas_used)
            .field("confirmation_count", &self.confirmation_count())
            .finish()
    }
}

/// Builder for creating transactions
pub struct TransactionBuilder {
    sender: Option<Vec<u8>>,
    nonce: Option<u64>,
    gas_limit: Option<u64>,
    gas_price: Option<u64>,
    transaction_type: Option<TransactionType>,
    data: Option<TransactionData>,
    privacy_level: u8,
    reads: HashSet<ObjectID>,
    writes: HashSet<ObjectID>,
    dependencies: Vec<TransactionDependency>,
    chain_id: Option<Vec<u8>>,
    metadata: HashMap<String, Vec<u8>>,
}

impl TransactionBuilder {
    /// Creates a new transaction builder
    pub fn new() -> Self {
        Self {
            sender: None,
            nonce: None,
            gas_limit: None,
            gas_price: None,
            transaction_type: None,
            data: None,
            privacy_level: 0,
            reads: HashSet::new(),
            writes: HashSet::new(),
            dependencies: Vec::new(),
            chain_id: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Sets the sender
    pub fn sender(mut self, sender: Vec<u8>) -> Self {
        self.sender = Some(sender);
        self
    }
    
    /// Sets the nonce
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }
    
    /// Sets the gas limit
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }
    
    /// Sets the gas price
    pub fn gas_price(mut self, gas_price: u64) -> Self {
        self.gas_price = Some(gas_price);
        self
    }
    
    /// Sets the transaction type
    pub fn transaction_type(mut self, transaction_type: TransactionType) -> Self {
        self.transaction_type = Some(transaction_type);
        self
    }
    
    /// Sets the transaction data
    pub fn data(mut self, data: TransactionData) -> Self {
        self.transaction_type = Some(data.transaction_type());
        self.data = Some(data);
        self
    }
    
    /// Sets the privacy level
    pub fn privacy_level(mut self, level: u8) -> Self {
        self.privacy_level = level;
        self
    }
    
    /// Adds an object to the read set
    pub fn read(mut self, object_id: ObjectID) -> Self {
        self.reads.insert(object_id);
        self
    }
    
    /// Adds an object to the write set
    pub fn write(mut self, object_id: ObjectID) -> Self {
        self.writes.insert(object_id);
        self
    }
    
    /// Adds a dependency
    pub fn dependency(mut self, dependency: TransactionDependency) -> Self {
        self.dependencies.push(dependency);
        self
    }
    
    /// Sets the chain ID
    pub fn chain_id(mut self, chain_id: Vec<u8>) -> Self {
        self.chain_id = Some(chain_id);
        self
    }
    
    /// Adds metadata
    pub fn metadata(mut self, key: String, value: Vec<u8>) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Builds the transaction
    pub fn build(self) -> Result<Transaction> {
        // Validate required fields
        let sender = self.sender.ok_or_else(|| AevorError::validation("Sender is required"))?;
        let nonce = self.nonce.ok_or_else(|| AevorError::validation("Nonce is required"))?;
        let gas_limit = self.gas_limit.ok_or_else(|| AevorError::validation("Gas limit is required"))?;
        let gas_price = self.gas_price.ok_or_else(|| AevorError::validation("Gas price is required"))?;
        let transaction_type = self.transaction_type.ok_or_else(|| AevorError::validation("Transaction type is required"))?;
        let data = self.data.ok_or_else(|| AevorError::validation("Transaction data is required"))?;
        let chain_id = self.chain_id.ok_or_else(|| AevorError::validation("Chain ID is required"))?;
        
        // Validate that transaction type matches data
        if transaction_type != data.transaction_type() {
            return Err(AevorError::validation("Transaction type does not match data"));
        }
        
        // Create the transaction
        let mut tx = Transaction::new(
            sender,
            nonce,
            gas_limit,
            gas_price,
            transaction_type,
            data,
            chain_id,
        );
        
        // Set optional fields
        tx.set_privacy_level(self.privacy_level);
        
        // Add reads and writes
        for id in self.reads {
            tx.add_read(id);
        }
        
        for id in self.writes {
            tx.add_write(id);
        }
        
        // Add dependencies
        for dep in self.dependencies {
            tx.add_dependency(dep);
        }
        
        // Add metadata
        for (key, value) in self.metadata {
            tx.add_metadata(key, value);
        }
        
        // Validate the transaction
        tx.validate_basic()?;
        
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::data::TransferData;
    
    #[test]
    fn test_transaction_hash() {
        let tx1 = create_test_transaction();
        let hash1 = tx1.hash();
        
        // Same transaction should have the same hash
        let hash2 = tx1.hash();
        assert_eq!(hash1, hash2);
        
        // Different transaction should have different hash
        let mut tx2 = create_test_transaction();
        tx2.nonce = 2;
        let hash3 = tx2.hash();
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_transaction_signature() {
        let mut tx = create_test_transaction();
        
        // Generate a test key pair
        let private_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let public_key = vec![3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34];
        
        // Sign the transaction
        let result = tx.sign(&private_key);
        assert!(result.is_ok());
        assert!(tx.signature.is_some());
        
        // This test can't actually verify the signature since we need real crypto implementation
        // In a real implementation, we would verify the signature here
    }
    
    #[test]
    fn test_transaction_dependencies() {
        let mut tx1 = create_test_transaction();
        let mut tx2 = create_test_transaction();
        
        // Set different object IDs
        let object1 = ObjectID(vec![1, 1, 1, 1]);
        let object2 = ObjectID(vec![2, 2, 2, 2]);
        
        // tx1 writes to object1
        tx1.add_write(object1.clone());
        
        // tx2 reads from object1 (RAW dependency)
        tx2.add_read(object1.clone());
        
        // Compute dependency
        let dep_type = tx2.compute_dependency(&tx1);
        assert_eq!(dep_type, DependencyType::ReadAfterWrite);
        
        // tx2 also writes to object2
        tx2.add_write(object2.clone());
        
        // tx1 reads from object2 (WAR dependency)
        tx1.add_read(object2.clone());
        
        // Compute dependency again (it should be the strongest dependency type)
        let dep_type = tx2.compute_dependency(&tx1);
        assert_eq!(dep_type, DependencyType::ReadAfterWrite);
    }
    
    #[test]
    fn test_transaction_builder() {
        let sender = vec![1, 2, 3, 4];
        let nonce = 1;
        let gas_limit = 100000;
        let gas_price = 1;
        let chain_id = vec![5, 6, 7, 8];
        
        let recipient = vec![9, 10, 11, 12];
        let amount = 1000;
        
        // Create transaction data
        let data = TransactionData::Transfer(TransferData {
            recipient: recipient.clone(),
            amount,
        });
        
        // Create transaction builder
        let builder = TransactionBuilder::new()
            .sender(sender.clone())
            .nonce(nonce)
            .gas_limit(gas_limit)
            .gas_price(gas_price)
            .data(data.clone())
            .chain_id(chain_id.clone());
        
        // Build the transaction
        let tx = builder.build().unwrap();
        
        // Verify transaction fields
        assert_eq!(tx.sender(), &sender);
        assert_eq!(tx.nonce(), nonce);
        assert_eq!(tx.gas_limit(), gas_limit);
        assert_eq!(tx.gas_price(), gas_price);
        assert_eq!(tx.transaction_type(), TransactionType::Transfer);
        assert_eq!(tx.data(), &data);
        assert_eq!(tx.chain_id(), &chain_id);
        assert_eq!(tx.status(), TransactionStatus::Pending);
    }
    
    // Helper function to create a test transaction
    fn create_test_transaction() -> Transaction {
        let sender = vec![1, 2, 3, 4];
        let recipient = vec![5, 6, 7, 8];
        let amount = 100;
        let data = TransactionData::Transfer(TransferData {
            recipient,
            amount,
        });
        
        Transaction::new(
            sender,
            1, // nonce
            100000, // gas_limit
            1, // gas_price
            TransactionType::Transfer,
            data,
            vec![9, 10, 11, 12], // chain_id
        )
    }
}
