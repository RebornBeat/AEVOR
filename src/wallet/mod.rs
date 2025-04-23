// Aevor Wallet Module
//
// This module provides wallet functionality for the Aevor blockchain,
// including account management, key storage, and transaction signing.

use std::path::PathBuf;
use std::sync::Arc;

use crate::error::{AevorError, Result};
use crate::crypto::keys::{KeyManager, PrivateKey, PublicKey};
use crate::core::transaction::Transaction;

pub mod account;
pub mod keystore;

use account::{Account, AccountType, AccountInfo};
use keystore::{KeyStore, StoredAccount, WalletConfig, KeyDerivationConfig};

/// Wallet for managing accounts and signing transactions
pub struct Wallet {
    /// Key store for managing accounts
    keystore: Arc<KeyStore>,
    
    /// Whether the wallet is locked
    locked: bool,
    
    /// Base directory for wallet data
    wallet_dir: PathBuf,
}

impl Wallet {
    /// Creates a new wallet with the given configuration
    pub fn new(config: WalletConfig, wallet_dir: PathBuf) -> Result<Self> {
        let keystore = KeyStore::new(config, wallet_dir.clone())?;
        
        Ok(Self {
            keystore: Arc::new(keystore),
            locked: true,
            wallet_dir,
        })
    }
    
    /// Opens an existing wallet from the specified directory
    pub fn open(wallet_dir: PathBuf) -> Result<Self> {
        let keystore = KeyStore::open(wallet_dir.clone())?;
        
        Ok(Self {
            keystore: Arc::new(keystore),
            locked: true,
            wallet_dir,
        })
    }
    
    /// Creates a new account
    pub fn create_account(
        &self,
        password: &str,
        account_type: AccountType,
        name: Option<String>,
    ) -> Result<Account> {
        if self.locked {
            return Err(AevorError::wallet("Wallet is locked"));
        }
        
        self.keystore.create_account(password, account_type, name)
    }
    
    /// Imports an account from a private key
    pub fn import_account(
        &self,
        private_key: &[u8],
        password: &str,
        account_type: AccountType,
        name: Option<String>,
    ) -> Result<Account> {
        if self.locked {
            return Err(AevorError::wallet("Wallet is locked"));
        }
        
        self.keystore.import_account(private_key, password, account_type, name)
    }
    
    /// Gets an account by its ID or address
    pub fn get_account(&self, id_or_address: &str) -> Result<Account> {
        self.keystore.get_account(id_or_address)
    }
    
    /// Gets all accounts
    pub fn get_all_accounts(&self) -> Result<Vec<Account>> {
        self.keystore.get_all_accounts()
    }
    
    /// Gets the default account
    pub fn get_default_account(&self) -> Result<Account> {
        self.keystore.get_default_account()
    }
    
    /// Sets the default account
    pub fn set_default_account(&self, account_id: &str) -> Result<()> {
        self.keystore.set_default_account(account_id)
    }
    
    /// Unlocks the wallet with the provided password
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        // Verify the password by trying to unlock any account
        let accounts = self.keystore.get_all_accounts()?;
        if let Some(account) = accounts.first() {
            // Try to unlock the account to verify the password
            self.keystore.unlock_account(&account.id(), password)?;
            // Lock it back immediately
            self.keystore.lock_account(&account.id())?;
        }
        
        // If we get here, the password is correct
        self.locked = false;
        Ok(())
    }
    
    /// Locks the wallet
    pub fn lock(&mut self) -> Result<()> {
        // Lock all accounts
        self.keystore.lock_all_accounts()?;
        self.locked = true;
        Ok(())
    }
    
    /// Unlocks an account with the provided password
    pub fn unlock_account(&self, account_id: &str, password: &str) -> Result<()> {
        if self.locked {
            return Err(AevorError::wallet("Wallet is locked"));
        }
        
        self.keystore.unlock_account(account_id, password)
    }
    
    /// Locks an account
    pub fn lock_account(&self, account_id: &str) -> Result<()> {
        self.keystore.lock_account(account_id)
    }
    
    /// Signs a transaction with the specified account
    pub fn sign_transaction(&self, transaction: &mut Transaction, account_id: &str) -> Result<()> {
        if self.locked {
            return Err(AevorError::wallet("Wallet is locked"));
        }
        
        // Get the account
        let account = self.get_account(account_id)?;
        
        // Check if the account is unlocked
        if account.is_locked() {
            return Err(AevorError::wallet("Account is locked"));
        }
        
        // Sign the transaction
        account.sign_transaction(transaction)
    }
    
    /// Signs data with the specified account
    pub fn sign_data(&self, data: &[u8], account_id: &str) -> Result<Vec<u8>> {
        if self.locked {
            return Err(AevorError::wallet("Wallet is locked"));
        }
        
        // Get the account
        let account = self.get_account(account_id)?;
        
        // Check if the account is unlocked
        if account.is_locked() {
            return Err(AevorError::wallet("Account is locked"));
        }
        
        // Sign the data
        account.sign(data)
    }
    
    /// Changes the password for an account
    pub fn change_password(
        &self,
        account_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        if self.locked {
            return Err(AevorError::wallet("Wallet is locked"));
        }
        
        self.keystore.change_password(account_id, old_password, new_password)
    }
    
    /// Updates account metadata
    pub fn update_account_metadata(
        &self,
        account_id: &str,
        name: Option<String>,
        metadata: Option<Vec<(String, Vec<u8>)>>,
    ) -> Result<()> {
        if self.locked {
            return Err(AevorError::wallet("Wallet is locked"));
        }
        
        self.keystore.update_account_metadata(account_id, name, metadata)
    }
    
    /// Deletes an account
    pub fn delete_account(&self, account_id: &str, password: &str) -> Result<()> {
        if self.locked {
            return Err(AevorError::wallet("Wallet is locked"));
        }
        
        self.keystore.delete_account(account_id, password)
    }
    
    /// Gets the wallet configuration
    pub fn config(&self) -> &WalletConfig {
        &self.keystore.config()
    }
    
    /// Gets the wallet directory
    pub fn wallet_dir(&self) -> &PathBuf {
        &self.wallet_dir
    }
    
    /// Checks if the wallet is locked
    pub fn is_locked(&self) -> bool {
        self.locked
    }
    
    /// Gets the keystore
    pub fn keystore(&self) -> Arc<KeyStore> {
        self.keystore.clone()
    }
}

/// Factory for creating or opening wallets
pub struct WalletFactory;

impl WalletFactory {
    /// Creates a new wallet with the given configuration
    pub fn create_wallet(
        config: WalletConfig,
        wallet_dir: PathBuf,
        password: &str,
    ) -> Result<Wallet> {
        // Create the wallet
        let mut wallet = Wallet::new(config, wallet_dir)?;
        
        // Unlock the wallet
        wallet.unlock(password)?;
        
        // Create a default account
        wallet.create_account(password, AccountType::User, Some("Default Account".to_string()))?;
        
        Ok(wallet)
    }
    
    /// Opens an existing wallet
    pub fn open_wallet(wallet_dir: PathBuf) -> Result<Wallet> {
        Wallet::open(wallet_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    fn create_test_wallet() -> (Wallet, PathBuf, String) {
        let dir = tempdir().unwrap();
        let wallet_dir = dir.path().to_path_buf();
        let password = "test_password".to_string();
        
        let config = WalletConfig {
            name: "Test Wallet".to_string(),
            version: "1.0.0".to_string(),
            default_account: None,
            key_derivation: KeyDerivationConfig::default(),
            auto_lock_timeout: 0,
            use_hardware_wallet: false,
        };
        
        let wallet = WalletFactory::create_wallet(config, wallet_dir.clone(), &password).unwrap();
        
        (wallet, wallet_dir, password)
    }
    
    #[test]
    fn test_wallet_creation() {
        let (wallet, _, _) = create_test_wallet();
        
        // The wallet should be unlocked after creation
        assert!(!wallet.is_locked());
        
        // There should be one account
        let accounts = wallet.get_all_accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        
        // The account should be the default
        let default = wallet.get_default_account().unwrap();
        assert_eq!(default.id(), accounts[0].id());
    }
    
    #[test]
    fn test_wallet_lock_unlock() {
        let (mut wallet, _, password) = create_test_wallet();
        
        // Lock the wallet
        wallet.lock().unwrap();
        assert!(wallet.is_locked());
        
        // Unlock the wallet
        wallet.unlock(&password).unwrap();
        assert!(!wallet.is_locked());
        
        // Try to unlock with wrong password
        let mut wallet2 = wallet;
        wallet2.lock().unwrap();
        assert!(wallet2.unlock("wrong_password").is_err());
        assert!(wallet2.is_locked());
    }
    
    #[test]
    fn test_account_management() {
        let (wallet, _, password) = create_test_wallet();
        
        // Create a new account
        let account = wallet.create_account(&password, AccountType::User, Some("Test Account".to_string())).unwrap();
        
        // Get the account
        let retrieved = wallet.get_account(&account.id()).unwrap();
        assert_eq!(retrieved.id(), account.id());
        
        // Get all accounts
        let accounts = wallet.get_all_accounts().unwrap();
        assert_eq!(accounts.len(), 2); // Default + new account
        
        // Set as default
        wallet.set_default_account(&account.id()).unwrap();
        let default = wallet.get_default_account().unwrap();
        assert_eq!(default.id(), account.id());
        
        // Update metadata
        wallet.update_account_metadata(&account.id(), Some("Updated Account".to_string()), None).unwrap();
        let updated = wallet.get_account(&account.id()).unwrap();
        assert_eq!(updated.name(), "Updated Account");
        
        // Delete the account
        wallet.delete_account(&account.id(), &password).unwrap();
        let accounts = wallet.get_all_accounts().unwrap();
        assert_eq!(accounts.len(), 1); // Only default account remains
    }
    
    #[test]
    fn test_account_locking() {
        let (wallet, _, password) = create_test_wallet();
        
        // Get the default account
        let account = wallet.get_default_account().unwrap();
        
        // Lock the account
        wallet.lock_account(&account.id()).unwrap();
        
        // Try to sign data (should fail because account is locked)
        let data = b"test data";
        assert!(wallet.sign_data(data, &account.id()).is_err());
        
        // Unlock the account
        wallet.unlock_account(&account.id(), &password).unwrap();
        
        // Now signing should work
        let signature = wallet.sign_data(data, &account.id());
        assert!(signature.is_ok());
    }
}
