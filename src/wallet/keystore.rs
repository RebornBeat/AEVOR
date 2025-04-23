use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::crypto::keys::{KeyManager, PrivateKey, PublicKey};
use crate::crypto::signature::SignatureAlgorithm;
use crate::error::{AevorError, Result};
use crate::wallet::account::{Account, AccountInfo, AccountType};

/// Configuration settings for the wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Wallet name
    pub name: String,
    
    /// Wallet version
    pub version: String,
    
    /// ID of the default account
    pub default_account: Option<String>,
    
    /// Settings for key derivation
    pub key_derivation: KeyDerivationConfig,
    
    /// Auto-lock timeout in seconds (0 = never)
    pub auto_lock_timeout: u64,
    
    /// Whether to use a hardware wallet if available
    pub use_hardware_wallet: bool,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            name: "Aevor Wallet".to_string(),
            version: "1.0.0".to_string(),
            default_account: None,
            key_derivation: KeyDerivationConfig::default(),
            auto_lock_timeout: 300, // 5 minutes
            use_hardware_wallet: false,
        }
    }
}

/// Configuration for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationConfig {
    /// Memory cost parameter for Argon2
    pub memory_cost: u32,
    
    /// Time cost parameter for Argon2
    pub time_cost: u32,
    
    /// Parallelism parameter for Argon2
    pub parallelism: u32,
}

impl Default for KeyDerivationConfig {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

/// Account metadata stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAccount {
    /// Account ID
    pub id: String,
    
    /// Account public key
    pub public_key: PublicKey,
    
    /// Account metadata
    pub info: AccountInfo,
    
    /// Encrypted private key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_key: Option<Vec<u8>>,
}

impl StoredAccount {
    /// Creates a new stored account from an account
    pub fn from_account(account: &Account, encrypted_key: Option<Vec<u8>>) -> Self {
        Self {
            id: account.id().to_string(),
            public_key: account.public_key().clone(),
            info: account.info().clone(),
            encrypted_key,
        }
    }
}

/// Key store for managing accounts and keys
pub struct KeyStore {
    /// Wallet configuration
    config: WalletConfig,
    
    /// Path to the wallet directory
    wallet_dir: PathBuf,
    
    /// In-memory cache of accounts by ID
    accounts: RwLock<HashMap<String, Account>>,
    
    /// Key manager for cryptographic operations
    key_manager: Arc<KeyManager>,
}

impl KeyStore {
    /// Creates a new key store
    pub fn new(config: WalletConfig, wallet_dir: PathBuf) -> Result<Self> {
        // Create directories if they don't exist
        fs::create_dir_all(&wallet_dir)?;
        fs::create_dir_all(wallet_dir.join("accounts"))?;
        fs::create_dir_all(wallet_dir.join("keys"))?;
        
        // Save the configuration
        let config_path = wallet_dir.join("config.json");
        let config_json = serde_json::to_string_pretty(&config)
            .map_err(|e| AevorError::wallet(format!("Failed to serialize config: {}", e)))?;
        
        let mut file = File::create(config_path)
            .map_err(|e| AevorError::wallet(format!("Failed to create config file: {}", e)))?;
        
        file.write_all(config_json.as_bytes())
            .map_err(|e| AevorError::wallet(format!("Failed to write config file: {}", e)))?;
        
        // Initialize the key manager
        let key_manager = Arc::new(KeyManager::new(wallet_dir.join("keys"))?);
        
        Ok(Self {
            config,
            wallet_dir,
            accounts: RwLock::new(HashMap::new()),
            key_manager,
        })
    }
    
    /// Opens an existing key store
    pub fn open(wallet_dir: PathBuf) -> Result<Self> {
        // Check if the wallet directory exists
        if !wallet_dir.exists() {
            return Err(AevorError::wallet(format!("Wallet directory does not exist: {}", wallet_dir.display())));
        }
        
        // Load the configuration
        let config_path = wallet_dir.join("config.json");
        let mut file = File::open(&config_path)
            .map_err(|e| AevorError::wallet(format!("Failed to open config file: {}", e)))?;
        
        let mut config_json = String::new();
        file.read_to_string(&mut config_json)
            .map_err(|e| AevorError::wallet(format!("Failed to read config file: {}", e)))?;
        
        let config: WalletConfig = serde_json::from_str(&config_json)
            .map_err(|e| AevorError::wallet(format!("Failed to parse config: {}", e)))?;
        
        // Initialize the key manager
        let key_manager = Arc::new(KeyManager::new(wallet_dir.join("keys"))?);
        
        // Create the key store
        let keystore = Self {
            config,
            wallet_dir,
            accounts: RwLock::new(HashMap::new()),
            key_manager,
        };
        
        // Load the accounts
        keystore.load_accounts()?;
        
        Ok(keystore)
    }
    
    /// Creates a new account
    pub fn create_account(
        &self,
        password: &str,
        account_type: AccountType,
        name: Option<String>,
    ) -> Result<Account> {
        // Generate a new key pair
        let private_key = PrivateKey::generate(SignatureAlgorithm::ED25519)
            .map_err(|e| AevorError::crypto("Failed to generate private key".into(), e.to_string(), None))?;
        
        let public_key = private_key.derive_public_key()
            .map_err(|e| AevorError::crypto("Failed to derive public key".into(), e.to_string(), None))?;
        
        // Create a new account
        let id = uuid::Uuid::new_v4().to_string();
        let info = AccountInfo::new(account_type, name);
        let account = Account::new(
            id.clone(),
            public_key.clone(),
            Some(private_key.clone()),
            info,
        );
        
        // Store the account
        self.store_account(&account, Some(password))?;
        
        // Set as default if no default account exists
        if self.config.default_account.is_none() {
            self.set_default_account(&id)?;
        }
        
        Ok(account)
    }
    
    /// Imports an account from a private key
    pub fn import_account(
        &self,
        private_key_bytes: &[u8],
        password: &str,
        account_type: AccountType,
        name: Option<String>,
    ) -> Result<Account> {
        // Create a private key from the bytes
        let private_key = PrivateKey::from_bytes(SignatureAlgorithm::ED25519, private_key_bytes)
            .map_err(|e| AevorError::crypto("Failed to import private key".into(), e.to_string(), None))?;
        
        // Derive the public key
        let public_key = private_key.derive_public_key()
            .map_err(|e| AevorError::crypto("Failed to derive public key".into(), e.to_string(), None))?;
        
        // Create a new account
        let id = uuid::Uuid::new_v4().to_string();
        let info = AccountInfo::new(account_type, name);
        let account = Account::new(
            id.clone(),
            public_key.clone(),
            Some(private_key.clone()),
            info,
        );
        
        // Store the account
        self.store_account(&account, Some(password))?;
        
        // Set as default if no default account exists
        if self.config.default_account.is_none() {
            self.set_default_account(&id)?;
        }
        
        Ok(account)
    }
    
    /// Gets an account by its ID or address
    pub fn get_account(&self, id_or_address: &str) -> Result<Account> {
        let accounts = self.accounts.read();
        
        // Try to find the account by ID
        if let Some(account) = accounts.get(id_or_address) {
            return Ok(account.clone());
        }
        
        // Try to find the account by address (hex string)
        if let Ok(address) = hex::decode(id_or_address) {
            for account in accounts.values() {
                if account.is_address(&address) {
                    return Ok(account.clone());
                }
            }
        }
        
        Err(AevorError::wallet(format!("Account not found: {}", id_or_address)))
    }
    
    /// Gets all accounts
    pub fn get_all_accounts(&self) -> Result<Vec<Account>> {
        let accounts = self.accounts.read();
        let accounts: Vec<Account> = accounts.values().cloned().collect();
        Ok(accounts)
    }
    
    /// Gets the default account
    pub fn get_default_account(&self) -> Result<Account> {
        if let Some(default_id) = &self.config.default_account {
            self.get_account(default_id)
        } else {
            Err(AevorError::wallet("No default account set"))
        }
    }
    
    /// Sets the default account
    pub fn set_default_account(&self, account_id: &str) -> Result<()> {
        // Check if the account exists
        let _ = self.get_account(account_id)?;
        
        // Update the configuration
        let mut config = self.config.clone();
        config.default_account = Some(account_id.to_string());
        
        // Save the configuration
        let config_path = self.wallet_dir.join("config.json");
        let config_json = serde_json::to_string_pretty(&config)
            .map_err(|e| AevorError::wallet(format!("Failed to serialize config: {}", e)))?;
        
        let mut file = File::create(config_path)
            .map_err(|e| AevorError::wallet(format!("Failed to create config file: {}", e)))?;
        
        file.write_all(config_json.as_bytes())
            .map_err(|e| AevorError::wallet(format!("Failed to write config file: {}", e)))?;
        
        // Update the in-memory configuration
        // In a more sophisticated implementation, this would use an atomic update
        let mut self_config = unsafe { &mut *(&self.config as *const WalletConfig as *mut WalletConfig) };
        *self_config = config;
        
        Ok(())
    }
    
    /// Unlocks an account with the provided password
    pub fn unlock_account(&self, account_id: &str, password: &str) -> Result<()> {
        // Get the account
        let mut accounts = self.accounts.write();
        let account = accounts.get_mut(account_id)
            .ok_or_else(|| AevorError::wallet(format!("Account not found: {}", account_id)))?;
        
        // If the account is already unlocked, return
        if !account.is_locked() {
            return Ok(());
        }
        
        // Get the account file path
        let account_path = self.get_account_path(account_id);
        
        // Load the stored account
        let stored_account = self.load_stored_account(&account_path)?;
        
        // Check if the account has an encrypted key
        let encrypted_key = stored_account.encrypted_key
            .ok_or_else(|| AevorError::wallet("Account has no encrypted key"))?;
        
        // Decrypt the private key
        let private_key = self.key_manager.decrypt_private_key(&encrypted_key, password)
            .map_err(|e| AevorError::wallet(format!("Failed to decrypt private key: {}", e)))?;
        
        // Unlock the account
        account.unlock(private_key)?;
        
        Ok(())
    }
    
    /// Locks an account
    pub fn lock_account(&self, account_id: &str) -> Result<()> {
        // Get the account
        let mut accounts = self.accounts.write();
        let account = accounts.get_mut(account_id)
            .ok_or_else(|| AevorError::wallet(format!("Account not found: {}", account_id)))?;
        
        // Lock the account
        account.lock();
        
        Ok(())
    }
    
    /// Locks all accounts
    pub fn lock_all_accounts(&self) -> Result<()> {
        let mut accounts = self.accounts.write();
        
        for account in accounts.values_mut() {
            account.lock();
        }
        
        Ok(())
    }
    
    /// Signs data with an account
    pub fn sign(&self, account_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        // Get the account
        let accounts = self.accounts.read();
        let account = accounts.get(account_id)
            .ok_or_else(|| AevorError::wallet(format!("Account not found: {}", account_id)))?;
        
        // Sign the data
        account.sign(data)
    }
    
    /// Updates account metadata
    pub fn update_account_metadata(
        &self,
        account_id: &str,
        name: Option<String>,
        metadata: Option<Vec<(String, Vec<u8>)>>,
    ) -> Result<()> {
        // Get the account
        let mut accounts = self.accounts.write();
        let account = accounts.get_mut(account_id)
            .ok_or_else(|| AevorError::wallet(format!("Account not found: {}", account_id)))?;
        
        // Update the account name
        if let Some(name) = name {
            account.set_name(Some(name));
        }
        
        // Update the account metadata
        if let Some(metadata) = metadata {
            for (key, value) in metadata {
                account.add_metadata(key, value);
            }
        }
        
        // Store the updated account
        self.store_account(account, None)?;
        
        Ok(())
    }
    
    /// Deletes an account
    pub fn delete_account(&self, account_id: &str, password: &str) -> Result<()> {
        // Verify the password by trying to unlock the account
        self.unlock_account(account_id, password)?;
        
        // Remove the account from the in-memory cache
        let mut accounts = self.accounts.write();
        accounts.remove(account_id);
        
        // Delete the account file
        let account_path = self.get_account_path(account_id);
        if account_path.exists() {
            fs::remove_file(account_path)
                .map_err(|e| AevorError::wallet(format!("Failed to delete account file: {}", e)))?;
        }
        
        // If this was the default account, clear the default
        if let Some(default_id) = &self.config.default_account {
            if default_id == account_id {
                let mut config = self.config.clone();
                config.default_account = None;
                
                // Save the configuration
                let config_path = self.wallet_dir.join("config.json");
                let config_json = serde_json::to_string_pretty(&config)
                    .map_err(|e| AevorError::wallet(format!("Failed to serialize config: {}", e)))?;
                
                let mut file = File::create(config_path)
                    .map_err(|e| AevorError::wallet(format!("Failed to create config file: {}", e)))?;
                
                file.write_all(config_json.as_bytes())
                    .map_err(|e| AevorError::wallet(format!("Failed to write config file: {}", e)))?;
                
                // Update the in-memory configuration
                let mut self_config = unsafe { &mut *(&self.config as *const WalletConfig as *mut WalletConfig) };
                *self_config = config;
            }
        }
        
        Ok(())
    }
    
    /// Changes the password for an account
    pub fn change_password(
        &self,
        account_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        // Unlock the account with the old password
        self.unlock_account(account_id, old_password)?;
        
        // Get the account
        let accounts = self.accounts.read();
        let account = accounts.get(account_id)
            .ok_or_else(|| AevorError::wallet(format!("Account not found: {}", account_id)))?;
        
        // Store the account with the new password
        self.store_account(account, Some(new_password))?;
        
        Ok(())
    }
    
    /// Loads all accounts from disk
    fn load_accounts(&self) -> Result<()> {
        let accounts_dir = self.wallet_dir.join("accounts");
        
        // Check if the accounts directory exists
        if !accounts_dir.exists() {
            return Ok(());
        }
        
        // Read all account files
        for entry in fs::read_dir(accounts_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            // Skip non-JSON files
            if !path.is_file() || path.extension().map_or(true, |ext| ext != "json") {
                continue;
            }
            
            // Load the stored account
            let stored_account = self.load_stored_account(&path)?;
            
            // Create the account (locked)
            let account = Account::new(
                stored_account.id.clone(),
                stored_account.public_key,
                None, // Account is locked initially
                stored_account.info,
            );
            
            // Add the account to the cache
            let mut accounts = self.accounts.write();
            accounts.insert(account.id().to_string(), account);
        }
        
        Ok(())
    }
    
    /// Loads a stored account from disk
    fn load_stored_account(&self, path: &Path) -> Result<StoredAccount> {
        // Read the account file
        let mut file = File::open(path)
            .map_err(|e| AevorError::wallet(format!("Failed to open account file: {}", e)))?;
        
        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| AevorError::wallet(format!("Failed to read account file: {}", e)))?;
        
        // Parse the JSON
        let stored_account: StoredAccount = serde_json::from_str(&content)
            .map_err(|e| AevorError::wallet(format!("Failed to parse account file: {}", e)))?;
        
        Ok(stored_account)
    }
    
    /// Stores an account to disk
    fn store_account(&self, account: &Account, password: Option<&str>) -> Result<()> {
        let mut encrypted_key = None;
        
        // Encrypt the private key if a password is provided and the account is unlocked
        if let Some(password) = password {
            if !account.is_locked() {
                // Get the private key
                let private_key = account.sign(&[0])
                    .map_err(|_| AevorError::wallet("Failed to get private key from account"))?;
                
                // Encrypt the private key
                encrypted_key = Some(self.key_manager.encrypt_private_key(&private_key, password)
                    .map_err(|e| AevorError::wallet(format!("Failed to encrypt private key: {}", e)))?);
            }
        }
        
        // Create the stored account
        let stored_account = StoredAccount::from_account(account, encrypted_key);
        
        // Serialize to JSON
        let json = serde_json::to_string_pretty(&stored_account)
            .map_err(|e| AevorError::wallet(format!("Failed to serialize account: {}", e)))?;
        
        // Write to file
        let account_path = self.get_account_path(account.id());
        let mut file = File::create(account_path)
            .map_err(|e| AevorError::wallet(format!("Failed to create account file: {}", e)))?;
        
        file.write_all(json.as_bytes())
            .map_err(|e| AevorError::wallet(format!("Failed to write account file: {}", e)))?;
        
        Ok(())
    }
    
    /// Gets the file path for an account
    fn get_account_path(&self, account_id: &str) -> PathBuf {
        self.wallet_dir.join("accounts").join(format!("{}.json", account_id))
    }
    
    /// Gets the wallet configuration
    pub fn config(&self) -> &WalletConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_keystore_creation() {
        let dir = tempdir().unwrap();
        let wallet_dir = dir.path().to_path_buf();
        
        let config = WalletConfig::default();
        let keystore = KeyStore::new(config.clone(), wallet_dir.clone()).unwrap();
        
        // Check that the directories were created
        assert!(wallet_dir.exists());
        assert!(wallet_dir.join("accounts").exists());
        assert!(wallet_dir.join("keys").exists());
        
        // Check that the config file was created
        assert!(wallet_dir.join("config.json").exists());
        
        // Check that the keystore has the correct config
        assert_eq!(keystore.config().name, config.name);
    }
}
