use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::transaction::Transaction;
use crate::crypto::hash::{Hash, HashAlgorithm, Hashable};
use crate::crypto::keys::{PrivateKey, PublicKey};
use crate::crypto::signature::{Signature, SignatureAlgorithm};
use crate::error::{AevorError, Result};

/// Represents a type of account
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccountType {
    /// Standard user account
    User,
    
    /// Validator account
    Validator,
    
    /// Smart contract account
    Contract,
    
    /// Multi-signature account
    MultiSig,
}

impl Default for AccountType {
    fn default() -> Self {
        AccountType::User
    }
}

impl fmt::Display for AccountType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountType::User => write!(f, "User"),
            AccountType::Validator => write!(f, "Validator"),
            AccountType::Contract => write!(f, "Contract"),
            AccountType::MultiSig => write!(f, "MultiSig"),
        }
    }
}

/// Account metadata and balance information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Account name
    pub name: Option<String>,
    
    /// Account type
    pub account_type: AccountType,
    
    /// Account balance
    pub balance: u64,
    
    /// Account nonce (number of transactions sent)
    pub nonce: u64,
    
    /// Creation time
    pub created_at: DateTime<Utc>,
    
    /// Last updated time
    pub updated_at: DateTime<Utc>,
    
    /// Account metadata (arbitrary key-value pairs)
    pub metadata: HashMap<String, Vec<u8>>,
}

impl AccountInfo {
    /// Creates a new account info
    pub fn new(account_type: AccountType, name: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            name,
            account_type,
            balance: 0,
            nonce: 0,
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }
    
    /// Updates the balance
    pub fn update_balance(&mut self, new_balance: u64) {
        self.balance = new_balance;
        self.updated_at = Utc::now();
    }
    
    /// Increments the nonce
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
        self.updated_at = Utc::now();
    }
    
    /// Gets the current nonce
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
    
    /// Gets the current balance
    pub fn balance(&self) -> u64 {
        self.balance
    }
    
    /// Gets the account type
    pub fn account_type(&self) -> AccountType {
        self.account_type
    }
    
    /// Gets the account name
    pub fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }
    
    /// Sets the account name
    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
        self.updated_at = Utc::now();
    }
    
    /// Adds metadata to the account
    pub fn add_metadata(&mut self, key: String, value: Vec<u8>) {
        self.metadata.insert(key, value);
        self.updated_at = Utc::now();
    }
    
    /// Gets metadata from the account
    pub fn get_metadata(&self, key: &str) -> Option<&Vec<u8>> {
        self.metadata.get(key)
    }
    
    /// Removes metadata from the account
    pub fn remove_metadata(&mut self, key: &str) -> Option<Vec<u8>> {
        let value = self.metadata.remove(key);
        if value.is_some() {
            self.updated_at = Utc::now();
        }
        value
    }
    
    /// Gets all metadata
    pub fn metadata(&self) -> &HashMap<String, Vec<u8>> {
        &self.metadata
    }
    
    /// Updates all metadata
    pub fn update_metadata(&mut self, metadata: HashMap<String, Vec<u8>>) {
        self.metadata = metadata;
        self.updated_at = Utc::now();
    }
}

/// Represents an account in the Aevor blockchain
#[derive(Clone, Serialize, Deserialize)]
pub struct Account {
    /// Unique account identifier (UUID)
    id: String,
    
    /// Account address derived from public key
    address: Vec<u8>,
    
    /// Account public key
    public_key: PublicKey,
    
    /// Account private key (only present if account is unlocked)
    #[serde(skip)]
    private_key: Option<PrivateKey>,
    
    /// Account information
    info: AccountInfo,
}

impl Account {
    /// Creates a new account with the given keys and info
    pub fn new(
        id: String,
        public_key: PublicKey,
        private_key: Option<PrivateKey>,
        info: AccountInfo,
    ) -> Self {
        let address = derive_address_from_public_key(&public_key);
        
        Self {
            id,
            address,
            public_key,
            private_key,
            info,
        }
    }
    
    /// Gets the account ID
    pub fn id(&self) -> &str {
        &self.id
    }
    
    /// Gets the account address
    pub fn address(&self) -> &[u8] {
        &self.address
    }
    
    /// Gets the account address as a hex string
    pub fn address_hex(&self) -> String {
        hex::encode(&self.address)
    }
    
    /// Gets the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    
    /// Gets the account info
    pub fn info(&self) -> &AccountInfo {
        &self.info
    }
    
    /// Gets a mutable reference to the account info
    pub fn info_mut(&mut self) -> &mut AccountInfo {
        &mut self.info
    }
    
    /// Checks if the account is locked
    pub fn is_locked(&self) -> bool {
        self.private_key.is_none()
    }
    
    /// Locks the account by removing the private key from memory
    pub fn lock(&mut self) {
        self.private_key = None;
    }
    
    /// Unlocks the account with a private key
    pub fn unlock(&mut self, private_key: PrivateKey) -> Result<()> {
        // Verify that the private key corresponds to the public key
        let derived_public_key = match private_key.derive_public_key() {
            Ok(pk) => pk,
            Err(e) => return Err(AevorError::crypto("Failed to derive public key".into(), e.to_string(), None)),
        };
        
        if derived_public_key.key() != self.public_key.key() {
            return Err(AevorError::wallet("Invalid private key for this account"));
        }
        
        self.private_key = Some(private_key);
        Ok(())
    }
    
    /// Signs data with the account's private key
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| AevorError::wallet("Account is locked"))?;
        
        let signature = Signature::sign(SignatureAlgorithm::ED25519, private_key.key(), data)
            .map_err(|e| AevorError::crypto("Signing failed".into(), e.to_string(), None))?;
        
        Ok(signature.value().to_vec())
    }
    
    /// Signs a transaction
    pub fn sign_transaction(&self, transaction: &mut Transaction) -> Result<()> {
        if self.is_locked() {
            return Err(AevorError::wallet("Account is locked"));
        }
        
        // Verify the transaction is from this account
        if transaction.sender() != self.address() {
            return Err(AevorError::validation("Transaction sender does not match account"));
        }
        
        // Sign the transaction
        let private_key = self.private_key.as_ref().unwrap();
        transaction.sign(private_key.key())?;
        
        // Increment the nonce (this would typically be done elsewhere in a real implementation)
        // self.info_mut().increment_nonce();
        
        Ok(())
    }
    
    /// Updates the account balance
    pub fn update_balance(&mut self, new_balance: u64) {
        self.info.update_balance(new_balance);
    }
    
    /// Increments the account nonce
    pub fn increment_nonce(&mut self) {
        self.info.increment_nonce();
    }
    
    /// Gets the current nonce
    pub fn nonce(&self) -> u64 {
        self.info.nonce()
    }
    
    /// Gets the current balance
    pub fn balance(&self) -> u64 {
        self.info.balance()
    }
    
    /// Gets the account type
    pub fn account_type(&self) -> AccountType {
        self.info.account_type()
    }
    
    /// Gets the account name
    pub fn name(&self) -> Option<&String> {
        self.info.name()
    }
    
    /// Sets the account name
    pub fn set_name(&mut self, name: Option<String>) {
        self.info.set_name(name);
    }
    
    /// Adds metadata to the account
    pub fn add_metadata(&mut self, key: String, value: Vec<u8>) {
        self.info.add_metadata(key, value);
    }
    
    /// Gets metadata from the account
    pub fn get_metadata(&self, key: &str) -> Option<&Vec<u8>> {
        self.info.get_metadata(key)
    }
    
    /// Checks if the address matches this account
    pub fn is_address(&self, address: &[u8]) -> bool {
        self.address == address
    }
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("address", &hex::encode(&self.address))
            .field("locked", &self.is_locked())
            .field("info", &self.info)
            .finish()
    }
}

impl Hashable for Account {
    fn hash_with_algorithm(&self, algorithm: HashAlgorithm) -> Hash {
        let mut hasher = Hash::new_hasher(algorithm);
        hasher.update(self.id.as_bytes());
        hasher.update(&self.address);
        hasher.update(self.public_key.key());
        
        // Hash account info
        hasher.update(&self.info.balance.to_le_bytes());
        hasher.update(&self.info.nonce.to_le_bytes());
        if let Some(name) = &self.info.name {
            hasher.update(name.as_bytes());
        }
        
        // Hash metadata (sort keys for deterministic order)
        let mut keys: Vec<&String> = self.info.metadata.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(self.info.metadata.get(key).unwrap());
        }
        
        Hash::new(algorithm, hasher.finalize())
    }
}

/// Derives an address from a public key
pub fn derive_address_from_public_key(public_key: &PublicKey) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    
    // Use SHA-256 to hash the public key
    let mut hasher = Sha256::new();
    hasher.update(public_key.key());
    let hash = hasher.finalize();
    
    // Take the first 20 bytes as the address (similar to Ethereum)
    hash[..20].to_vec()
}

/// Builder for creating accounts
pub struct AccountBuilder {
    id: Option<String>,
    public_key: Option<PublicKey>,
    private_key: Option<PrivateKey>,
    name: Option<String>,
    account_type: AccountType,
    balance: u64,
    nonce: u64,
    metadata: HashMap<String, Vec<u8>>,
}

impl AccountBuilder {
    /// Creates a new account builder
    pub fn new() -> Self {
        Self {
            id: None,
            public_key: None,
            private_key: None,
            name: None,
            account_type: AccountType::User,
            balance: 0,
            nonce: 0,
            metadata: HashMap::new(),
        }
    }
    
    /// Sets the account ID
    pub fn id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }
    
    /// Sets the public key
    pub fn public_key(mut self, public_key: PublicKey) -> Self {
        self.public_key = Some(public_key);
        self
    }
    
    /// Sets the private key
    pub fn private_key(mut self, private_key: Option<PrivateKey>) -> Self {
        self.private_key = private_key;
        self
    }
    
    /// Sets the account name
    pub fn name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }
    
    /// Sets the account type
    pub fn account_type(mut self, account_type: AccountType) -> Self {
        self.account_type = account_type;
        self
    }
    
    /// Sets the initial balance
    pub fn balance(mut self, balance: u64) -> Self {
        self.balance = balance;
        self
    }
    
    /// Sets the initial nonce
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }
    
    /// Adds metadata
    pub fn metadata(mut self, key: String, value: Vec<u8>) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Builds the account
    pub fn build(self) -> Result<Account> {
        let id = self.id.ok_or_else(|| AevorError::wallet("Account ID is required"))?;
        let public_key = self.public_key.ok_or_else(|| AevorError::wallet("Public key is required"))?;
        
        let mut info = AccountInfo::new(self.account_type, self.name);
        info.update_balance(self.balance);
        
        // Set nonce
        for _ in 0..self.nonce {
            info.increment_nonce();
        }
        
        // Add metadata
        for (key, value) in self.metadata {
            info.add_metadata(key, value);
        }
        
        Ok(Account::new(
            id,
            public_key,
            self.private_key,
            info,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    
    fn create_test_keypair() -> (PublicKey, PrivateKey) {
        // In a real implementation, this would use proper crypto
        // For now, we'll create simple test keys
        let private_key = PrivateKey::generate(SignatureAlgorithm::ED25519)
            .expect("Failed to generate private key");
        let public_key = private_key.derive_public_key().unwrap();
        
        (public_key, private_key)
    }
    
    fn create_test_account() -> (Account, PrivateKey) {
        let (public_key, private_key) = create_test_keypair();
        
        let account = AccountBuilder::new()
            .id(Uuid::new_v4().to_string())
            .public_key(public_key)
            .private_key(Some(private_key.clone()))
            .name(Some("Test Account".to_string()))
            .account_type(AccountType::User)
            .build()
            .unwrap();
        
        (account, private_key)
    }
    
    #[test]
    fn test_account_address() {
        let (account, _) = create_test_account();
        
        // Check that the address was derived correctly
        let derived_address = derive_address_from_public_key(account.public_key());
        assert_eq!(account.address(), &derived_address);
        
        // Check address hex string
        assert_eq!(account.address_hex(), hex::encode(account.address()));
        
        // Check is_address method
        assert!(account.is_address(account.address()));
        assert!(!account.is_address(b"wrong address"));
    }
    
    #[test]
    fn test_account_balance_and_nonce() {
        let (mut account, _) = create_test_account();
        
        // Update balance
        account.update_balance(1000);
        assert_eq!(account.balance(), 1000);
        
        // Increment nonce
        account.increment_nonce();
        assert_eq!(account.nonce(), 1);
        
        account.increment_nonce();
        assert_eq!(account.nonce(), 2);
    }
    
    #[test]
    fn test_account_metadata() {
        let (mut account, _) = create_test_account();
        
        // Add metadata
        account.add_metadata("test_key".to_string(), b"test_value".to_vec());
        assert_eq!(account.get_metadata("test_key"), Some(&b"test_value".to_vec()));
        
        // Add more metadata
        account.add_metadata("test_key2".to_string(), b"test_value2".to_vec());
        assert_eq!(account.get_metadata("test_key2"), Some(&b"test_value2".to_vec()));
        
        // Update metadata
        account.add_metadata("test_key".to_string(), b"new_value".to_vec());
        assert_eq!(account.get_metadata("test_key"), Some(&b"new_value".to_vec()));
        
        // Non-existent metadata
        assert_eq!(account.get_metadata("nonexistent"), None);
        
        // Test accessing all metadata
        let metadata = account.info().metadata();
        assert_eq!(metadata.len(), 2);
        assert_eq!(metadata.get("test_key"), Some(&b"new_value".to_vec()));
        assert_eq!(metadata.get("test_key2"), Some(&b"test_value2".to_vec()));
    }
    
    #[test]
    fn test_account_builder() {
        let (public_key, private_key) = create_test_keypair();
        let id = Uuid::new_v4().to_string();
        
        // Build an account with all options
        let account = AccountBuilder::new()
            .id(id.clone())
            .public_key(public_key.clone())
            .private_key(Some(private_key.clone()))
            .name(Some("Test Account".to_string()))
            .account_type(AccountType::Validator)
            .balance(1000)
            .nonce(5)
            .metadata("test_key".to_string(), b"test_value".to_vec())
            .build()
            .unwrap();
        
        // Verify all options were set correctly
        assert_eq!(account.id(), &id);
        assert_eq!(account.public_key().key(), public_key.key());
        assert!(!account.is_locked()); // Has private key
        assert_eq!(account.name(), Some(&"Test Account".to_string()));
        assert_eq!(account.account_type(), AccountType::Validator);
        assert_eq!(account.balance(), 1000);
        assert_eq!(account.nonce(), 5);
        assert_eq!(account.get_metadata("test_key"), Some(&b"test_value".to_vec()));
        
        // Test builder without required fields
        let result = AccountBuilder::new()
            .name(Some("Test Account".to_string()))
            .build();
        assert!(result.is_err()); // Missing ID and public key
        
        let result = AccountBuilder::new()
            .id(Uuid::new_v4().to_string())
            .build();
        assert!(result.is_err()); // Missing public key
    }
    
    #[test]
    fn test_account_hashable() {
        let (account, _) = create_test_account();
        
        // Hash the account
        let hash = account.hash_with_algorithm(HashAlgorithm::SHA256);
        
        // Hashing the same account again should produce the same hash
        let hash2 = account.hash_with_algorithm(HashAlgorithm::SHA256);
        assert_eq!(hash.value, hash2.value);
        
        // Modifying the account should change the hash
        let mut account2 = account.clone();
        account2.update_balance(1000);
        let hash3 = account2.hash_with_algorithm(HashAlgorithm::SHA256);
        assert_ne!(hash.value, hash3.value);
    }
    
    #[test]
    fn test_account_info() {
        // Create account info
        let now = Utc::now();
        let mut info = AccountInfo::new(AccountType::User, Some("Test Account".to_string()));
        
        // Check default values
        assert_eq!(info.name, Some("Test Account".to_string()));
        assert_eq!(info.account_type, AccountType::User);
        assert_eq!(info.balance, 0);
        assert_eq!(info.nonce, 0);
        assert!(info.created_at >= now); // Should be after or equal to 'now'
        assert!(info.metadata.is_empty());
        
        // Update balance
        info.update_balance(1000);
        assert_eq!(info.balance, 1000);
        
        // Increment nonce
        info.increment_nonce();
        assert_eq!(info.nonce, 1);
        
        // Add metadata
        info.add_metadata("test_key".to_string(), b"test_value".to_vec());
        assert_eq!(info.get_metadata("test_key"), Some(&b"test_value".to_vec()));
        
        // Remove metadata
        let removed = info.remove_metadata("test_key");
        assert_eq!(removed, Some(b"test_value".to_vec()));
        assert_eq!(info.get_metadata("test_key"), None);
        
        // Update metadata
        let mut new_metadata = HashMap::new();
        new_metadata.insert("key1".to_string(), b"value1".to_vec());
        new_metadata.insert("key2".to_string(), b"value2".to_vec());
        info.update_metadata(new_metadata);
        
        assert_eq!(info.metadata.len(), 2);
        assert_eq!(info.get_metadata("key1"), Some(&b"value1".to_vec()));
        assert_eq!(info.get_metadata("key2"), Some(&b"value2".to_vec()));
    }
    
    #[test]
    fn test_account_type_display() {
        assert_eq!(AccountType::User.to_string(), "User");
        assert_eq!(AccountType::Validator.to_string(), "Validator");
        assert_eq!(AccountType::Contract.to_string(), "Contract");
        assert_eq!(AccountType::MultiSig.to_string(), "MultiSig");
    }
    
    #[test]
    fn test_account_type_default() {
        assert_eq!(AccountType::default(), AccountType::User);
    }
}
