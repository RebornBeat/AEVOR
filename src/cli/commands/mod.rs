use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::AevorConfig;
use crate::error::{AevorError, Result};

// Import subcommands
mod node;
mod wallet;
mod chain;
mod contract;
mod utils;
mod validator;
mod transaction;

// Re-export all command implementations
pub use node::NodeCommand;
pub use wallet::WalletCommand;
pub use chain::ChainCommand;
pub use contract::ContractCommand;
pub use utils::UtilsCommand;
pub use validator::ValidatorCommand;
pub use transaction::TransactionCommand;

/// Aevor Blockchain CLI
#[derive(Debug, Parser)]
#[clap(name = "aevor", version, about, author)]
pub struct CliCommand {
    /// Path to the configuration file
    #[clap(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    
    /// Enable verbose output
    #[clap(short, long)]
    pub verbose: bool,
    
    /// Log level (trace, debug, info, warn, error)
    #[clap(long, default_value = "info")]
    pub log_level: String,
    
    /// Subcommand to execute
    #[clap(subcommand)]
    pub command: Command,
}

/// Available subcommands
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start an Aevor node
    #[clap(name = "start")]
    Start(NodeCommand),
    
    /// Wallet management commands
    #[clap(name = "wallet")]
    Wallet(WalletCommand),
    
    /// Chain interaction commands
    #[clap(name = "chain")]
    Chain(ChainCommand),
    
    /// Smart contract interaction commands
    #[clap(name = "contract")]
    Contract(ContractCommand),
    
    /// Utility commands
    #[clap(name = "utils")]
    Utils(UtilsCommand),
    
    /// Validator management commands
    #[clap(name = "validator")]
    Validator(ValidatorCommand),
    
    /// Transaction management commands
    #[clap(name = "tx")]
    Transaction(TransactionCommand),
}

impl CliCommand {
    /// Execute the CLI command
    pub async fn execute(self, config: Arc<AevorConfig>) -> Result<()> {
        // Set log level based on verbosity and log_level options
        let log_level = if self.verbose {
            "debug"
        } else {
            &self.log_level
        };
        
        // Initialize logging
        crate::cli::init_cli_logger(log_level)?;
        
        // Execute the appropriate subcommand
        match self.command {
            Command::Start(cmd) => cmd.execute(config).await,
            Command::Wallet(cmd) => cmd.execute(config).await,
            Command::Chain(cmd) => cmd.execute(config).await,
            Command::Contract(cmd) => cmd.execute(config).await,
            Command::Utils(cmd) => cmd.execute(config).await,
            Command::Validator(cmd) => cmd.execute(config).await,
            Command::Transaction(cmd) => cmd.execute(config).await,
        }
    }
    
    /// Get the configuration path from the command line
    pub fn config_path(&self) -> Option<&PathBuf> {
        self.config.as_ref()
    }
}

/// Trait for command execution
#[async_trait::async_trait]
pub trait CommandExecutor {
    /// Execute the command
    async fn execute(&self, config: Arc<AevorConfig>) -> Result<()>;
}
