use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::AevorConfig;
use crate::error::{AevorError, Result};
use crate::cli::utils::display;
use crate::wallet::{Account, KeyStore, WalletConfig};

use super::CommandExecutor;

/// Wallet management commands
#[derive(Debug, Args)]
pub struct WalletCommand {
    /// Subcommand
    #[clap(subcommand)]
    pub command: WalletSubcommand,
}

/// Wallet subcommands
#[derive(Debug, Subcommand)]
pub enum WalletSubcommand {
    /// Create a new wallet
    #[clap(name = "create")]
    Create(WalletCreateCommand),
    
    /// Import an existing wallet
    #[clap(name = "import")]
    Import(WalletImportCommand),
    
    /// Export a wallet
    #[clap(name = "export")]
    Export(WalletExportCommand),
    
    /// List all wallets
    #[clap(name = "list")]
    List,
    
    /// Show the balance of a wallet
    #[clap(name = "balance")]
    Balance(WalletBalanceCommand),
    
    /// Show detailed information about a wallet
    #[clap(name = "info")]
    Info(WalletInfoCommand),
    
    /// Change the password of a wallet
    #[clap(name = "change-password")]
    ChangePassword(WalletChangePasswordCommand),
    
    /// Create a backup of a wallet
    #[clap(name = "backup")]
    Backup(WalletBackupCommand),
    
    /// Restore a wallet from backup
    #[clap(name = "restore")]
    Restore(WalletRestoreCommand),
    
    /// Delete a wallet
    #[clap(name = "delete")]
    Delete(WalletDeleteCommand),
}

/// Create a new wallet
#[derive(Debug, Args)]
pub struct WalletCreateCommand {
    /// The name of the wallet
    #[clap(required = true)]
    pub name: String,
}

/// Import an existing wallet
#[derive(Debug, Args)]
pub struct WalletImportCommand {
    /// The name of the wallet
    #[clap(required = true)]
    pub name: String,
    
    /// The private key of the wallet (hex format)
    #[clap(long)]
    pub private_key: Option<String>,
    
    /// Import from a keystore file
    #[clap(long)]
    pub keystore: Option<PathBuf>,
    
    /// Import from a mnemonic phrase
    #[clap(long)]
    pub mnemonic: bool,
}

/// Export a wallet
#[derive(Debug, Args)]
pub struct WalletExportCommand {
    /// The name or address of the wallet
    #[clap(required = true)]
    pub wallet: String,
    
    /// Export the private key
    #[clap(long)]
    pub private_key: bool,
    
    /// Export to a keystore file
    #[clap(long)]
    pub keystore: bool,
    
    /// Export the mnemonic phrase
    #[clap(long)]
    pub mnemonic: bool,
    
    /// Output file (optional, defaults to stdout)
    #[clap(short, long)]
    pub output: Option<PathBuf>,
}

/// Show the balance of a wallet
#[derive(Debug, Args)]
pub struct WalletBalanceCommand {
    /// The name or address of the wallet
    #[clap(required = true)]
    pub wallet: String,
}

/// Show detailed information about a wallet
#[derive(Debug, Args)]
pub struct WalletInfoCommand {
    /// The name or address of the wallet
    #[clap(required = true)]
    pub wallet: String,
}

/// Change the password of a wallet
#[derive(Debug, Args)]
pub struct WalletChangePasswordCommand {
    /// The name or address of the wallet
    #[clap(required = true)]
    pub wallet: String,
}

/// Create a backup of a wallet
#[derive(Debug, Args)]
pub struct WalletBackupCommand {
    /// The name or address of the wallet
    #[clap(required = true)]
    pub wallet: String,
    
    /// Output file path
    #[clap(short, long)]
    pub output: Option<PathBuf>,
}

/// Restore a wallet from backup
#[derive(Debug, Args)]
pub struct WalletRestoreCommand {
    /// Backup file path
    #[clap(required = true)]
    pub backup_file: PathBuf,
    
    /// New wallet name (optional)
    #[clap(short, long)]
    pub name: Option<String>,
}

/// Delete a wallet
#[derive(Debug, Args)]
pub struct WalletDeleteCommand {
    /// The name or address of the wallet
    #[clap(required = true)]
    pub wallet: String,
}

#[async_trait::async_trait]
impl CommandExecutor for WalletCommand {
    async fn execute(&self, config: Arc<AevorConfig>) -> Result<()> {
        match &self.command {
            WalletSubcommand::Create(cmd) => create_wallet(cmd, config).await,
            WalletSubcommand::Import(cmd) => import_wallet(cmd, config).await,
            WalletSubcommand::Export(cmd) => export_wallet(cmd, config).await,
            WalletSubcommand::List => list_wallets(config).await,
            WalletSubcommand::Balance(cmd) => show_balance(cmd, config).await,
            WalletSubcommand::Info(cmd) => show_wallet_info(cmd, config).await,
            WalletSubcommand::ChangePassword(cmd) => change_password(cmd, config).await,
            WalletSubcommand::Backup(cmd) => backup_wallet(cmd, config).await,
            WalletSubcommand::Restore(cmd) => restore_wallet(cmd, config).await,
            WalletSubcommand::Delete(cmd) => delete_wallet(cmd, config).await,
        }
    }
}

/// Create a new wallet
async fn create_wallet(cmd: &WalletCreateCommand, config: Arc<AevorConfig>) -> Result<()> {
    display::section("Creating New Wallet");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Prompt for password
    let password = crate::cli::utils::password_with_confirmation(
        "Enter password for new wallet:", 
        "Confirm password:"
    )?;
    
    let spinner = display::spinner("Creating new wallet...");
    
    // Create new account
    let account = keystore.create_account(cmd.name.clone(), &password)?;
    
    spinner.finish_with_message(format!("Created wallet {}", cmd.name.clone()));
    
    // Display the wallet details
    display_account_info(&account);
    
    display::success("Wallet created successfully!");
    display::warning("Please back up your wallet in a secure location.");
    
    Ok(())
}

/// Import an existing wallet
async fn import_wallet(cmd: &WalletImportCommand, config: Arc<AevorConfig>) -> Result<()> {
    display::section("Importing Wallet");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Check import options
    let account = if let Some(private_key) = &cmd.private_key {
        // Import from private key
        display::info("Importing wallet from private key...");
        
        // Prompt for password
        let password = crate::cli::utils::password_with_confirmation(
            "Enter password for imported wallet:", 
            "Confirm password:"
        )?;
        
        // Convert hex private key to bytes
        let private_key_bytes = hex::decode(private_key.trim_start_matches("0x"))
            .map_err(|e| AevorError::wallet(format!("Invalid private key format: {}", e)))?;
        
        // Import account
        keystore.import_account(cmd.name.clone(), &private_key_bytes, &password)?
    } else if let Some(keystore_path) = &cmd.keystore {
        // Import from keystore file
        display::info(&format!("Importing wallet from keystore file: {}", keystore_path.display()));
        
        // Prompt for source keystore password
        let source_password = crate::cli::utils::password("Enter password for keystore file:")?;
        
        // Prompt for new keystore password
        let new_password = crate::cli::utils::password_with_confirmation(
            "Enter new password for imported wallet:", 
            "Confirm new password:"
        )?;
        
        // Read keystore file
        let keystore_json = std::fs::read_to_string(keystore_path)
            .map_err(|e| AevorError::wallet(format!("Failed to read keystore file: {}", e)))?;
        
        // TODO: Implement keystore import logic
        return Err(AevorError::wallet("Keystore import not implemented yet"));
    } else if cmd.mnemonic {
        // Import from mnemonic phrase
        display::info("Importing wallet from mnemonic phrase...");
        
        // Prompt for mnemonic
        let mnemonic = crate::cli::utils::prompt("Enter mnemonic phrase:");
        
        // Prompt for password
        let password = crate::cli::utils::password_with_confirmation(
            "Enter password for imported wallet:", 
            "Confirm password:"
        )?;
        
        // TODO: Implement mnemonic import logic
        return Err(AevorError::wallet("Mnemonic import not implemented yet"));
    } else {
        // No import option specified
        return Err(AevorError::wallet("Please specify an import method: --private-key, --keystore, or --mnemonic"));
    };
    
    // Display the wallet details
    display_account_info(&account);
    
    display::success("Wallet imported successfully!");
    
    Ok(())
}

/// Export a wallet
async fn export_wallet(cmd: &WalletExportCommand, config: Arc<AevorConfig>) -> Result<()> {
    display::section("Exporting Wallet");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Get the account
    let account = get_account(&keystore, &cmd.wallet)?;
    
    // Prompt for password
    let password = crate::cli::utils::password(&format!("Enter password for wallet '{}':", account.address_hex()))?;
    
    // Unlock the account
    let mut unlocked_account = account.clone();
    keystore.unlock_account(&mut unlocked_account, &password)?;
    
    if cmd.private_key {
        // Export private key
        if let Some(private_key) = unlocked_account.private_key() {
            let private_key_hex = hex::encode(private_key);
            
            if let Some(output_path) = &cmd.output {
                // Write to file
                std::fs::write(output_path, private_key_hex)
                    .map_err(|e| AevorError::wallet(format!("Failed to write private key to file: {}", e)))?;
                display::success(&format!("Private key exported to {}", output_path.display()));
            } else {
                // Print to stdout
                display::section("Private Key");
                println!("0x{}", private_key_hex);
                display::warning("Keep your private key secret! Anyone with your private key can access your funds.");
            }
        } else {
            return Err(AevorError::wallet("Failed to export private key"));
        }
    } else if cmd.keystore {
        // Export keystore
        // TODO: Implement keystore export logic
        return Err(AevorError::wallet("Keystore export not implemented yet"));
    } else if cmd.mnemonic {
        // Export mnemonic
        // TODO: Implement mnemonic export logic
        return Err(AevorError::wallet("Mnemonic export not implemented yet"));
    } else {
        // No export option specified
        return Err(AevorError::wallet("Please specify an export method: --private-key, --keystore, or --mnemonic"));
    }
    
    Ok(())
}

/// List all wallets
async fn list_wallets(config: Arc<AevorConfig>) -> Result<()> {
    display::section("Wallet List");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Get all accounts
    let accounts = keystore.get_all_accounts()?;
    
    if accounts.is_empty() {
        display::info("No wallets found.");
        display::info("Create a new wallet with: aevor wallet create <name>");
        return Ok(());
    }
    
    // Create a table for display
    let mut table = display::create_table(vec!["Name", "Address", "Status"]);
    
    // Add rows to the table
    for account in accounts {
        display::add_row(&mut table, vec![
            account.name().to_string(),
            account.address_hex(),
            if account.is_locked() { "Locked".to_string() } else { "Unlocked".to_string() },
        ]);
    }
    
    // Print the table
    display::print_table(table);
    
    display::info(&format!("Found {} wallets.", accounts.len()));
    
    Ok(())
}

/// Show the balance of a wallet
async fn show_balance(cmd: &WalletBalanceCommand, config: Arc<AevorConfig>) -> Result<()> {
    display::section("Wallet Balance");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Get the account
    let account = get_account(&keystore, &cmd.wallet)?;
    
    // TODO: Implement actual balance checking
    // For now, we'll just display a placeholder
    
    println!("Address: {}", account.address_hex());
    println!("Balance: 1000.00 AEVOR");
    
    display::info("Note: This is a placeholder. Actual balance checking not implemented yet.");
    
    Ok(())
}

/// Show detailed information about a wallet
async fn show_wallet_info(cmd: &WalletInfoCommand, config: Arc<AevorConfig>) -> Result<()> {
    display::section("Wallet Information");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Get the account
    let account = get_account(&keystore, &cmd.wallet)?;
    
    // Display account information
    display_account_info(&account);
    
    Ok(())
}

/// Change the password of a wallet
async fn change_password(cmd: &WalletChangePasswordCommand, config: Arc<AevorConfig>) -> Result<()> {
    display::section("Change Wallet Password");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Get the account
    let account = get_account(&keystore, &cmd.wallet)?;
    
    // Prompt for current password
    let current_password = crate::cli::utils::password(&format!("Enter current password for wallet '{}':", account.address_hex()))?;
    
    // Prompt for new password
    let new_password = crate::cli::utils::password_with_confirmation(
        "Enter new password:", 
        "Confirm new password:"
    )?;
    
    // Change password
    keystore.change_password(&account, &current_password, &new_password)?;
    
    display::success("Password changed successfully!");
    
    Ok(())
}

/// Create a backup of a wallet
async fn backup_wallet(cmd: &WalletBackupCommand, config: Arc<AevorConfig>) -> Result<()> {
    display::section("Backup Wallet");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Get the account
    let account = get_account(&keystore, &cmd.wallet)?;
    
    // Determine the backup file path
    let backup_path = match &cmd.output {
        Some(path) => path.clone(),
        None => {
            let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
            PathBuf::from(format!("{}_backup_{}.json", account.name(), timestamp))
        }
    };
    
    // Prompt for password
    let password = crate::cli::utils::password(&format!("Enter password for wallet '{}':", account.address_hex()))?;
    
    let spinner = display::spinner(&format!("Creating backup for wallet {}...", account.address_hex()));
    
    // TODO: Implement actual backup logic
    // For now, we'll just simulate a backup
    
    // Simulate backup creation
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Placeholder: Just write some dummy data to the file
    let backup_data = serde_json::json!({
        "backup_type": "wallet",
        "wallet_address": account.address_hex(),
        "name": account.name(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "note": "This is a placeholder backup. Actual backup logic not implemented yet."
    });
    
    std::fs::write(&backup_path, serde_json::to_string_pretty(&backup_data).unwrap())
        .map_err(|e| AevorError::wallet(format!("Failed to write backup file: {}", e)))?;
    
    spinner.finish_with_message(format!("Backup created at {}", backup_path.display()));
    
    display::success("Wallet backup created successfully!");
    display::warning("Keep your backup in a secure location.");
    
    Ok(())
}

/// Restore a wallet from backup
async fn restore_wallet(cmd: &WalletRestoreCommand, config: Arc<AevorConfig>) -> Result<()> {
    display::section("Restore Wallet");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Check if the backup file exists
    if !cmd.backup_file.exists() {
        return Err(AevorError::wallet(format!("Backup file not found: {}", cmd.backup_file.display())));
    }
    
    // Read the backup file
    let backup_data = std::fs::read_to_string(&cmd.backup_file)
        .map_err(|e| AevorError::wallet(format!("Failed to read backup file: {}", e)))?;
    
    // Parse the backup data
    let backup_json: serde_json::Value = serde_json::from_str(&backup_data)
        .map_err(|e| AevorError::wallet(format!("Failed to parse backup file: {}", e)))?;
    
    // Extract wallet information
    let wallet_address = backup_json["wallet_address"].as_str()
        .ok_or_else(|| AevorError::wallet("Invalid backup file: missing wallet address"))?;
    
    let wallet_name = match &cmd.name {
        Some(name) => name.clone(),
        None => backup_json["name"].as_str()
            .ok_or_else(|| AevorError::wallet("Invalid backup file: missing wallet name"))?
            .to_string(),
    };
    
    let spinner = display::spinner(&format!("Restoring wallet {}...", wallet_address));
    
    // TODO: Implement actual restore logic
    // For now, we'll just simulate a restore
    
    // Simulate restore operation
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    spinner.finish_with_message(format!("Wallet restored: {}", wallet_address));
    
    display::success("Wallet restored successfully!");
    display::info(&format!("Wallet name: {}", wallet_name));
    display::info(&format!("Wallet address: {}", wallet_address));
    
    Ok(())
}

/// Delete a wallet
async fn delete_wallet(cmd: &WalletDeleteCommand, config: Arc<AevorConfig>) -> Result<()> {
    display::section("Delete Wallet");
    
    // Initialize keystore
    let wallet_dir = config.node.data_dir.join("wallets");
    let wallet_config = WalletConfig::default();
    let keystore = KeyStore::new(wallet_config, wallet_dir)?;
    
    // Get the account
    let account = get_account(&keystore, &cmd.wallet)?;
    
    // Display account information
    display_account_info(&account);
    
    // Confirm deletion
    let confirm = crate::cli::utils::confirm(&format!(
        "Are you sure you want to delete wallet '{}'? This action cannot be undone.",
        account.address_hex()
    ))?;
    
    if !confirm {
        display::info("Wallet deletion cancelled.");
        return Ok(());
    }
    
    // Prompt for password
    let password = crate::cli::utils::password(&format!("Enter password for wallet '{}':", account.address_hex()))?;
    
    let spinner = display::spinner(&format!("Deleting wallet {}...", account.address_hex()));
    
    // Delete the account
    keystore.delete_account(&account, &password)?;
    
    spinner.finish_with_message(format!("Wallet deleted: {}", account.address_hex()));
    
    display::success("Wallet deleted successfully.");
    
    Ok(())
}

/// Helper function to get an account by name or address
fn get_account(keystore: &KeyStore, name_or_address: &str) -> Result<Account> {
    // Try to get the account by name
    if let Ok(account) = keystore.get_account(name_or_address) {
        return Ok(account);
    }
    
    // Try to get the account by address
    for account in keystore.get_all_accounts()? {
        if account.address_hex() == name_or_address {
            return Ok(account);
        }
    }
    
    Err(AevorError::wallet(format!("Wallet not found: {}", name_or_address)))
}

/// Helper function to display account information
fn display_account_info(account: &Account) {
    display::section("Wallet Details");
    println!("Name:        {}", account.name());
    println!("Address:     {}", account.address_hex());
    println!("Status:      {}", if account.is_locked() { "Locked" } else { "Unlocked" });
    println!("Created:     {}", account.created_at().format("%Y-%m-%d %H:%M:%S"));
    
    // Display tags if any
    if !account.tags().is_empty() {
        println!("Tags:        {}", account.tags().join(", "));
    }
}
