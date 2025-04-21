use aevor::cli::commands::CliCommand;
use aevor::config::AevorConfig;
use clap::Parser;
use std::sync::Arc;
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Entry point for the Aevor blockchain application
#[tokio::main]
async fn main() {
    // Initialize logging with an environment filter
    init_logging();
    
    // Log application startup
    info!("Starting Aevor V1 blockchain node");
    debug!("Debug logging enabled");
    
    // Parse command-line arguments
    let cli_command = CliCommand::parse();
    
    // Load or create default configuration
    match load_config(&cli_command) {
        Ok(config) => {
            // Create a shareable reference to the configuration
            let config = Arc::new(config);
            
            // Execute the parsed CLI command
            if let Err(e) = cli_command.execute(config).await {
                error!("Failed to execute command: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    }
}

/// Initialize logging with tracing subscriber
fn init_logging() {
    // Create a logging filter from the RUST_LOG environment variable
    // or use "info" as the default log level
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    
    // Initialize the tracing subscriber with the filter and formatting
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();
}

/// Load configuration based on CLI arguments
fn load_config(cli_command: &CliCommand) -> aevor::error::Result<AevorConfig> {
    // Check if a configuration file path was provided in the CLI
    if let Some(config_path) = cli_command.config_path() {
        debug!("Loading configuration from: {}", config_path.display());
        AevorConfig::load_or_default(config_path)
    } else {
        // Use default configuration path
        let default_path = std::path::PathBuf::from("config.json");
        debug!("Loading configuration from default path: {}", default_path.display());
        AevorConfig::load_or_default(default_path)
    }
}
