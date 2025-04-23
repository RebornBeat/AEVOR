use async_trait::async_trait;
use clap::{Args, Subcommand};
use std::sync::Arc;

use crate::config::AevorConfig;
use crate::error::{AevorError, Result};
use crate::cli::utils::display;
use super::CommandExecutor;

/// Validator management commands
#[derive(Debug, Args)]
pub struct ValidatorCommand {
    /// Subcommand
    #[clap(subcommand)]
    pub command: ValidatorSubcommand,
}

/// Available validator subcommands
#[derive(Debug, Subcommand)]
pub enum ValidatorSubcommand {
    /// Register a new validator
    #[clap(name = "register")]
    Register(ValidatorRegisterCommand),
    
    /// View validator information
    #[clap(name = "info")]
    Info(ValidatorInfoCommand),
    
    /// List all validators
    #[clap(name = "list")]
    List(ValidatorListCommand),
    
    /// Check validator status
    #[clap(name = "status")]
    Status(ValidatorStatusCommand),
    
    /// Update validator configuration
    #[clap(name = "update")]
    Update(ValidatorUpdateCommand),
    
    /// View validator metrics
    #[clap(name = "metrics")]
    Metrics(ValidatorMetricsCommand),
    
    /// Manage validator keys
    #[clap(name = "keys")]
    Keys(ValidatorKeysCommand),
}

/// Register a new validator
#[derive(Debug, Args)]
pub struct ValidatorRegisterCommand {
    /// Validator name
    #[clap(long)]
    pub name: String,
    
    /// Wallet to use for staking
    #[clap(long)]
    pub wallet: String,
    
    /// Stake amount
    #[clap(long)]
    pub stake: u64,
    
    /// Commission rate (0-100%)
    #[clap(long, default_value = "10")]
    pub commission: u8,
    
    /// Website URL
    #[clap(long)]
    pub website: Option<String>,
    
    /// Description
    #[clap(long)]
    pub description: Option<String>,
    
    /// Force registration without confirmation
    #[clap(long)]
    pub force: bool,
}

/// View validator information
#[derive(Debug, Args)]
pub struct ValidatorInfoCommand {
    /// Validator address or name
    #[clap(long)]
    pub validator: String,
    
    /// Output format (json, table)
    #[clap(long, default_value = "table")]
    pub format: String,
}

/// List all validators
#[derive(Debug, Args)]
pub struct ValidatorListCommand {
    /// Filter by status (active, inactive, all)
    #[clap(long, default_value = "active")]
    pub status: String,
    
    /// Sort by field (name, stake, uptime)
    #[clap(long, default_value = "stake")]
    pub sort: String,
    
    /// Maximum number of validators to show
    #[clap(long)]
    pub limit: Option<usize>,
    
    /// Output format (json, table)
    #[clap(long, default_value = "table")]
    pub format: String,
}

/// Check validator status
#[derive(Debug, Args)]
pub struct ValidatorStatusCommand {
    /// Validator address or name
    #[clap(long)]
    pub validator: Option<String>,
    
    /// Show detailed information
    #[clap(long)]
    pub detailed: bool,
}

/// Update validator configuration
#[derive(Debug, Args)]
pub struct ValidatorUpdateCommand {
    /// Validator address or name
    #[clap(long)]
    pub validator: String,
    
    /// New validator name
    #[clap(long)]
    pub name: Option<String>,
    
    /// New commission rate (0-100%)
    #[clap(long)]
    pub commission: Option<u8>,
    
    /// New website URL
    #[clap(long)]
    pub website: Option<String>,
    
    /// New description
    #[clap(long)]
    pub description: Option<String>,
    
    /// Force update without confirmation
    #[clap(long)]
    pub force: bool,
}

/// View validator metrics
#[derive(Debug, Args)]
pub struct ValidatorMetricsCommand {
    /// Validator address or name
    #[clap(long)]
    pub validator: Option<String>,
    
    /// Time period (1h, 24h, 7d, 30d)
    #[clap(long, default_value = "24h")]
    pub period: String,
    
    /// Output format (json, table)
    #[clap(long, default_value = "table")]
    pub format: String,
}

/// Manage validator keys
#[derive(Debug, Args)]
pub struct ValidatorKeysCommand {
    /// Action (create, import, export, rotate)
    #[clap(subcommand)]
    pub action: ValidatorKeysAction,
}

/// Actions for validator keys
#[derive(Debug, Subcommand)]
pub enum ValidatorKeysAction {
    /// Create new validator keys
    #[clap(name = "create")]
    Create(ValidatorKeysCreateCommand),
    
    /// Import validator keys
    #[clap(name = "import")]
    Import(ValidatorKeysImportCommand),
    
    /// Export validator keys
    #[clap(name = "export")]
    Export(ValidatorKeysExportCommand),
    
    /// Rotate validator keys
    #[clap(name = "rotate")]
    Rotate(ValidatorKeysRotateCommand),
}

/// Create new validator keys
#[derive(Debug, Args)]
pub struct ValidatorKeysCreateCommand {
    /// Validator address or name
    #[clap(long)]
    pub validator: String,
    
    /// Key type (consensus, tee, network)
    #[clap(long, default_value = "consensus")]
    pub key_type: String,
    
    /// Output file
    #[clap(long)]
    pub output: Option<String>,
}

/// Import validator keys
#[derive(Debug, Args)]
pub struct ValidatorKeysImportCommand {
    /// Validator address or name
    #[clap(long)]
    pub validator: String,
    
    /// Key type (consensus, tee, network)
    #[clap(long, default_value = "consensus")]
    pub key_type: String,
    
    /// Input file
    #[clap(long)]
    pub input: String,
}

/// Export validator keys
#[derive(Debug, Args)]
pub struct ValidatorKeysExportCommand {
    /// Validator address or name
    #[clap(long)]
    pub validator: String,
    
    /// Key type (consensus, tee, network)
    #[clap(long, default_value = "consensus")]
    pub key_type: String,
    
    /// Output file
    #[clap(long)]
    pub output: Option<String>,
    
    /// Export private key (unsafe)
    #[clap(long)]
    pub private: bool,
}

/// Rotate validator keys
#[derive(Debug, Args)]
pub struct ValidatorKeysRotateCommand {
    /// Validator address or name
    #[clap(long)]
    pub validator: String,
    
    /// Key type (consensus, tee, network)
    #[clap(long, default_value = "consensus")]
    pub key_type: String,
    
    /// Force rotation without confirmation
    #[clap(long)]
    pub force: bool,
}

#[async_trait]
impl CommandExecutor for ValidatorCommand {
    async fn execute(&self, config: Arc<AevorConfig>) -> Result<()> {
        match &self.command {
            ValidatorSubcommand::Register(cmd) => self.register(cmd, config).await,
            ValidatorSubcommand::Info(cmd) => self.info(cmd, config).await,
            ValidatorSubcommand::List(cmd) => self.list(cmd, config).await,
            ValidatorSubcommand::Status(cmd) => self.status(cmd, config).await,
            ValidatorSubcommand::Update(cmd) => self.update(cmd, config).await,
            ValidatorSubcommand::Metrics(cmd) => self.metrics(cmd, config).await,
            ValidatorSubcommand::Keys(cmd) => self.keys(cmd, config).await,
        }
    }
}

impl ValidatorCommand {
    /// Register a new validator
    async fn register(&self, cmd: &ValidatorRegisterCommand, config: Arc<AevorConfig>) -> Result<()> {
        display::section("Validator Registration");
        
        // Check if commission rate is valid
        if cmd.commission > 100 {
            return Err(AevorError::validation("Commission rate must be between 0 and 100"));
        }
        
        // Check confirmation
        if !cmd.force {
            display::info(&format!("You are about to register a new validator:"));
            display::info(&format!("Name: {}", cmd.name));
            display::info(&format!("Wallet: {}", cmd.wallet));
            display::info(&format!("Stake: {} tokens", cmd.stake));
            display::info(&format!("Commission: {}%", cmd.commission));
            
            if !crate::cli::utils::confirm("Do you want to continue?") {
                display::info("Registration cancelled.");
                return Ok(());
            }
        }
        
        // In a real implementation, this would connect to the node and register the validator
        let spinner = display::spinner("Registering validator...");
        // Simulate registration process
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        spinner.finish_with_message("Validator registered successfully!");
        
        display::success(&format!("Validator '{}' has been registered with {} tokens stake.", cmd.name, cmd.stake));
        display::info("It may take a few minutes for the validator to appear in the active set.");
        
        Ok(())
    }
    
    /// View validator information
    async fn info(&self, cmd: &ValidatorInfoCommand, config: Arc<AevorConfig>) -> Result<()> {
        display::section(&format!("Validator Information: {}", cmd.validator));
        
        // In a real implementation, this would fetch validator info from the node
        let spinner = display::spinner("Fetching validator information...");
        // Simulate fetching data
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        spinner.finish_with_message("Information retrieved!");
        
        // Example validator data
        let data = serde_json::json!({
            "address": "aevor1validator9a8f7s6d5f4g3h2j1k",
            "name": "Awesome Validator",
            "status": "active",
            "stake": 1000000,
            "commission": 10,
            "delegations": 15,
            "total_delegated": 500000,
            "uptime": 99.98,
            "blocks_produced": 1234,
            "website": "https://awesome-validator.com",
            "description": "Professional validator service with 24/7 monitoring",
            "created_at": "2024-01-15T12:00:00Z",
        });
        
        // Display the data in the requested format
        if cmd.format == "json" {
            display::print_json(&data);
        } else {
            // Table format
            let mut table = display::create_table(vec!["Property", "Value"]);
            
            // Add all fields to the table
            if let Some(obj) = data.as_object() {
                for (key, value) in obj {
                    let formatted_key = key.replace("_", " ");
                    let formatted_key = formatted_key.chars().nth(0).unwrap().to_uppercase().to_string() + &formatted_key[1..];
                    
                    let value_str = match value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) if key == "stake" || key == "total_delegated" => 
                            format!("{} tokens", n),
                        serde_json::Value::Number(n) if key == "commission" || key == "uptime" => 
                            format!("{}%", n),
                        _ => value.to_string(),
                    };
                    
                    display::add_row(&mut table, vec![formatted_key, value_str]);
                }
            }
            
            display::print_table(table);
        }
        
        Ok(())
    }
    
    /// List all validators
    async fn list(&self, cmd: &ValidatorListCommand, config: Arc<AevorConfig>) -> Result<()> {
        display::section("Validators List");
        
        // In a real implementation, this would fetch validators from the node
        let spinner = display::spinner("Fetching validators...");
        // Simulate fetching data
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        spinner.finish_with_message("Retrieved validators!");
        
        // Example validators data
        let mut validators = vec![
            serde_json::json!({
                "address": "aevor1validator9a8f7s6d5f4g3h2j1k",
                "name": "Awesome Validator",
                "status": "active",
                "stake": 1000000,
                "commission": 10,
                "uptime": 99.98,
            }),
            serde_json::json!({
                "address": "aevor1validator8b7c6d5e4f3g2h1j",
                "name": "Super Node",
                "status": "active",
                "stake": 2000000,
                "commission": 5,
                "uptime": 99.95,
            }),
            serde_json::json!({
                "address": "aevor1validator7c6d5e4f3g2h1j0k",
                "name": "Validator Pro",
                "status": "active",
                "stake": 1500000,
                "commission": 8,
                "uptime": 99.90,
            }),
            serde_json::json!({
                "address": "aevor1validator6d5e4f3g2h1j0k9l",
                "name": "Inactive Node",
                "status": "inactive",
                "stake": 500000,
                "commission": 15,
                "uptime": 95.50,
            }),
        ];
        
        // Apply status filter
        if cmd.status != "all" {
            validators.retain(|v| {
                if let Some(status) = v.get("status") {
                    if let Some(status_str) = status.as_str() {
                        return status_str == cmd.status;
                    }
                }
                false
            });
        }
        
        // Apply sorting
        match cmd.sort.as_str() {
            "stake" => {
                validators.sort_by(|a, b| {
                    let a_stake = a.get("stake").and_then(|v| v.as_u64()).unwrap_or(0);
                    let b_stake = b.get("stake").and_then(|v| v.as_u64()).unwrap_or(0);
                    b_stake.cmp(&a_stake) // Descending order
                });
            },
            "name" => {
                validators.sort_by(|a, b| {
                    let a_name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let b_name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    a_name.cmp(b_name) // Ascending order
                });
            },
            "uptime" => {
                validators.sort_by(|a, b| {
                    let a_uptime = a.get("uptime").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let b_uptime = b.get("uptime").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    b_uptime.partial_cmp(&a_uptime).unwrap() // Descending order
                });
            },
            _ => {}
        }
        
        // Apply limit
        if let Some(limit) = cmd.limit {
            validators.truncate(limit);
        }
        
        // Display the data in the requested format
        if cmd.format == "json" {
            display::print_json(&serde_json::json!(validators));
        } else {
            // Table format
            let mut table = display::create_table(vec![
                "Name", "Address", "Status", "Stake", "Commission", "Uptime"
            ]);
            
            for validator in validators {
                let name = validator.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let address = validator.get("address").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let status = validator.get("status").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let stake = validator.get("stake").and_then(|v| v.as_u64()).unwrap_or(0);
                let commission = validator.get("commission").and_then(|v| v.as_u64()).unwrap_or(0);
                let uptime = validator.get("uptime").and_then(|v| v.as_f64()).unwrap_or(0.0);
                
                let status_formatted = crate::cli::utils::format_status(status);
                
                display::add_row(&mut table, vec![
                    name.to_string(),
                    crate::cli::utils::display::format_address(address.as_bytes()),
                    status_formatted.to_string(),
                    format!("{} tokens", stake),
                    format!("{}%", commission),
                    format!("{:.2}%", uptime),
                ]);
            }
            
            display::print_table(table);
            display::info(&format!("Showing {} validators", validators.len()));
        }
        
        Ok(())
    }
    
    /// Check validator status
    async fn status(&self, cmd: &ValidatorStatusCommand, config: Arc<AevorConfig>) -> Result<()> {
        let validator = match &cmd.validator {
            Some(v) => v.clone(),
            None => {
                // If no validator is specified, use the current node
                if !config.node.is_validator {
                    return Err(AevorError::validation("This node is not a validator"));
                }
                "This node".to_string()
            }
        };
        
        display::section(&format!("Validator Status: {}", validator));
        
        // In a real implementation, this would fetch validator status from the node
        let spinner = display::spinner("Checking validator status...");
        // Simulate fetching data
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        spinner.finish_with_message("Status retrieved!");
        
        let status = "active";
        let uptime = 99.98;
        let last_block = "#1234567";
        let peers = 25;
        let memory_usage = "1.2 GB";
        let cpu_usage = "15%";
        
        display::info(&format!("Status: {}", crate::cli::utils::format_status(status)));
        display::info(&format!("Uptime: {:.2}%", uptime));
        display::info(&format!("Last Block: {}", last_block));
        display::info(&format!("Connected Peers: {}", peers));
        
        if cmd.detailed {
            display::info(&format!("Memory Usage: {}", memory_usage));
            display::info(&format!("CPU Usage: {}", cpu_usage));
            display::info(&format!("Consensus Participation: Active"));
            display::info(&format!("TEE Status: Valid"));
            display::info(&format!("Network Health: Good"));
        }
        
        Ok(())
    }
    
    /// Update validator configuration
    async fn update(&self, cmd: &ValidatorUpdateCommand, config: Arc<AevorConfig>) -> Result<()> {
        display::section(&format!("Update Validator: {}", cmd.validator));
        
        // Check if there's anything to update
        if cmd.name.is_none() && cmd.commission.is_none() && cmd.website.is_none() && cmd.description.is_none() {
            return Err(AevorError::validation("No update parameters specified"));
        }
        
        // Check commission rate
        if let Some(commission) = cmd.commission {
            if commission > 100 {
                return Err(AevorError::validation("Commission rate must be between 0 and 100"));
            }
        }
        
        // Check confirmation
        if !cmd.force {
            display::info("You are about to update the validator with the following changes:");
            
            if let Some(name) = &cmd.name {
                display::info(&format!("Name: {}", name));
            }
            
            if let Some(commission) = cmd.commission {
                display::info(&format!("Commission: {}%", commission));
            }
            
            if let Some(website) = &cmd.website {
                display::info(&format!("Website: {}", website));
            }
            
            if let Some(description) = &cmd.description {
                display::info(&format!("Description: {}", description));
            }
            
            if !crate::cli::utils::confirm("Do you want to continue?") {
                display::info("Update cancelled.");
                return Ok(());
            }
        }
        
        // In a real implementation, this would connect to the node and update the validator
        let spinner = display::spinner("Updating validator...");
        // Simulate update process
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        spinner.finish_with_message("Validator updated successfully!");
        
        display::success(&format!("Validator '{}' has been updated.", cmd.validator));
        
        Ok(())
    }
    
    /// View validator metrics
    async fn metrics(&self, cmd: &ValidatorMetricsCommand, config: Arc<AevorConfig>) -> Result<()> {
        let validator = match &cmd.validator {
            Some(v) => v.clone(),
            None => {
                // If no validator is specified, use the current node
                if !config.node.is_validator {
                    return Err(AevorError::validation("This node is not a validator"));
                }
                "This node".to_string()
            }
        };
        
        display::section(&format!("Validator Metrics: {} ({})", validator, cmd.period));
        
        // In a real implementation, this would fetch validator metrics from the node
        let spinner = display::spinner("Fetching validator metrics...");
        // Simulate fetching data
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        spinner.finish_with_message("Metrics retrieved!");
        
        // Example metrics data
        let data = serde_json::json!({
            "blocks_proposed": 128,
            "blocks_validated": 1024,
            "transactions_processed": 23456,
            "average_block_time_ms": 524,
            "average_transaction_time_ms": 35,
            "reward_tokens": 15623,
            "uptime_percentage": 99.98,
            "slash_events": 0,
            "attestations_provided": 5280,
            "tee_verifications": 4096,
        });
        
        // Display the data in the requested format
        if cmd.format == "json" {
            display::print_json(&data);
        } else {
            // Table format
            let mut table = display::create_table(vec!["Metric", "Value"]);
            
            // Add all fields to the table
            if let Some(obj) = data.as_object() {
                for (key, value) in obj {
                    let formatted_key = key.replace("_", " ");
                    let formatted_key = formatted_key.chars().nth(0).unwrap().to_uppercase().to_string() + &formatted_key[1..];
                    
                    let value_str = match (key.as_str(), value) {
                        ("reward_tokens", serde_json::Value::Number(n)) => format!("{} tokens", n),
                        ("uptime_percentage", serde_json::Value::Number(n)) => format!("{}%", n),
                        ("average_block_time_ms", serde_json::Value::Number(n)) => format!("{} ms", n),
                        ("average_transaction_time_ms", serde_json::Value::Number(n)) => format!("{} ms", n),
                        _ => value.to_string(),
                    };
                    
                    display::add_row(&mut table, vec![formatted_key, value_str]);
                }
            }
            
            display::print_table(table);
        }
        
        Ok(())
    }
    
    /// Manage validator keys
    async fn keys(&self, cmd: &ValidatorKeysCommand, config: Arc<AevorConfig>) -> Result<()> {
        match &cmd.action {
            ValidatorKeysAction::Create(create_cmd) => {
                display::section(&format!("Create Validator Key: {}", create_cmd.key_type));
                
                // In a real implementation, this would create keys for the validator
                let spinner = display::spinner("Creating validator key...");
                // Simulate key creation
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                spinner.finish_with_message("Key created successfully!");
                
                let output_path = match &create_cmd.output {
                    Some(path) => path.clone(),
                    None => format!("{}_key.json", create_cmd.key_type),
                };
                
                display::success(&format!("Created new {} key for validator '{}'", create_cmd.key_type, create_cmd.validator));
                display::info(&format!("Public key: aevor1pubkey9a8f7s6d5f4g3h2j1k"));
                display::info(&format!("Key saved to: {}", output_path));
                display::warning("Keep your private key safe and secure!");
            },
            ValidatorKeysAction::Import(import_cmd) => {
                display::section(&format!("Import Validator Key: {}", import_cmd.key_type));
                
                // In a real implementation, this would import keys for the validator
                let spinner = display::spinner("Importing validator key...");
                // Simulate key import
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                spinner.finish_with_message("Key imported successfully!");
                
                display::success(&format!("Imported {} key for validator '{}'", import_cmd.key_type, import_cmd.validator));
                display::info(&format!("Public key: aevor1pubkey8b7c6d5e4f3g2h1j"));
            },
            ValidatorKeysAction::Export(export_cmd) => {
                display::section(&format!("Export Validator Key: {}", export_cmd.key_type));
                
                if export_cmd.private && !crate::cli::utils::confirm("Warning: You are about to export a private key. This is potentially unsafe. Continue?") {
                    display::info("Export cancelled.");
                    return Ok(());
                }
                
                // In a real implementation, this would export keys for the validator
                let spinner = display::spinner("Exporting validator key...");
                // Simulate key export
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                spinner.finish_with_message("Key exported successfully!");
                
                let output_path = match &export_cmd.output {
                    Some(path) => path.clone(),
                    None => format!("{}_key_export.json", export_cmd.key_type),
                };
                
                display::success(&format!("Exported {} key for validator '{}'", export_cmd.key_type, export_cmd.validator));
                display::info(&format!("Key saved to: {}", output_path));
                
                if export_cmd.private {
                    display::warning("This file contains private key material. Keep it secure!");
                }
            },
            ValidatorKeysAction::Rotate(rotate_cmd) => {
                display::section(&format!("Rotate Validator Key: {}", rotate_cmd.key_type));
                
                // Check confirmation
                if !rotate_cmd.force {
                    display::warning("Key rotation will change your validator's identity. This operation cannot be undone.");
                    display::info("Your validator will continue to function with the new key, but its identity will change.");
                    
                    if !crate::cli::utils::confirm("Do you want to continue?") {
                        display::info("Rotation cancelled.");
                        return Ok(());
                    }
                }
                
                // In a real implementation, this would rotate keys for the validator
                let spinner = display::spinner("Rotating validator key...");
                // Simulate key rotation
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                spinner.finish_with_message("Key rotated successfully!");
                
                display::success(&format!("Rotated {} key for validator '{}'", rotate_cmd.key_type, rotate_cmd.validator));
                display::info(&format!("New public key: aevor1pubkey7c6d5e4f3g2h1j0k"));
                display::info("The old key has been securely removed.");
                display::info("The rotation will take effect in the next epoch.");
            },
        }
        
        Ok(())
    }
}
