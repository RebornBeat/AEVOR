use std::sync::Arc;

use crate::config::AevorConfig;
use crate::error::Result;

// Public modules
pub mod commands;
pub mod utils;

// Re-export common items
pub use commands::CliCommand;
pub use utils::display;

/// Executes a CLI command with the given configuration
pub async fn execute_command(cmd: CliCommand, config: Arc<AevorConfig>) -> Result<()> {
    // Display the Aevor banner
    utils::display::show_banner();
    
    // Execute the command
    cmd.execute(config).await
}

/// Get a short description of the Aevor CLI
pub fn get_cli_description() -> &'static str {
    "Aevor - A high-performance blockchain with Dual-DAG Proof of Uncorruption"
}

/// Get the version of the Aevor CLI
pub fn get_cli_version() -> &'static str {
    crate::VERSION
}

/// Get the authors of the Aevor CLI
pub fn get_cli_authors() -> &'static str {
    "Aevor Team <info@aevor.io>"
}

/// Initialize the CLI logger
pub fn init_cli_logger(log_level: &str) -> Result<()> {
    // Create a filter based on the log level
    let filter = match log_level {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    
    // Initialize the subscriber
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    
    Ok(())
}
