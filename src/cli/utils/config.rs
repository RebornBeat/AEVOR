use std::path::{Path, PathBuf};
use std::fs;

use crate::config::AevorConfig;
use crate::error::{AevorError, Result};
use super::display;

/// Default configuration file name
pub const DEFAULT_CONFIG_FILENAME: &str = "config.json";

/// Get the default configuration path
pub fn get_default_config_path() -> PathBuf {
    let aevor_dir = super::get_aevor_dir();
    aevor_dir.join(DEFAULT_CONFIG_FILENAME)
}

/// Load or create a configuration file
pub fn load_or_create_config(config_path: Option<&Path>) -> Result<AevorConfig> {
    let path = match config_path {
        Some(p) => p.to_owned(),
        None => get_default_config_path(),
    };
    
    // If the directory doesn't exist, create it
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| AevorError::config(format!("Failed to create config directory: {}", e)))?;
        }
    }
    
    // Load or create the configuration
    if path.exists() {
        display::info(&format!("Loading configuration from {}", path.display()));
        AevorConfig::load(&path)
    } else {
        display::info("Creating new default configuration");
        let config = AevorConfig::default();
        config.save(&path)?;
        display::success(&format!("Created new configuration at {}", path.display()));
        Ok(config)
    }
}

/// Update specific configuration values
pub fn update_config_values(
    config: &mut AevorConfig,
    updates: &[(&str, &str)],
) -> Result<()> {
    for (key, value) in updates {
        match *key {
            // Node configuration
            "node.name" => config.node.name = value.to_string(),
            "node.log_level" => config.node.log_level = value.to_string(),
            "node.is_validator" => config.node.is_validator = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid boolean value: {}", e)))?,
            "node.max_memory_mb" => config.node.max_memory_mb = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid number: {}", e)))?,
            "node.worker_threads" => config.node.worker_threads = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid number: {}", e)))?,
            "node.metrics_enabled" => config.node.metrics_enabled = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid boolean value: {}", e)))?,
            
            // Network configuration
            "network.listen_addr" => config.network.listen_addr = value.to_string(),
            "network.p2p_port" => config.network.p2p_port = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid port number: {}", e)))?,
            "network.enable_upnp" => config.network.enable_upnp = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid boolean value: {}", e)))?,
            "network.max_peers" => config.network.max_peers = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid number: {}", e)))?,
            "network.enable_rdma_transport" => config.network.enable_rdma_transport = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid boolean value: {}", e)))?,
            
            // Consensus configuration
            "consensus.pou.use_tee" => config.consensus.pou.use_tee = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid boolean value: {}", e)))?,
            "consensus.pou.tee_type" => config.consensus.pou.tee_type = value.to_string(),
            "consensus.security_accelerator.enabled" => config.consensus.security_accelerator.enabled = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid boolean value: {}", e)))?,
                
            // API configuration
            "api.http_enabled" => config.api.http_enabled = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid boolean value: {}", e)))?,
            "api.http_port" => config.api.http_port = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid port number: {}", e)))?,
            "api.ws_enabled" => config.api.ws_enabled = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid boolean value: {}", e)))?,
            "api.ws_port" => config.api.ws_port = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid port number: {}", e)))?,
            
            // Storage configuration
            "storage.engine" => config.storage.engine = value.to_string(),
            
            // VM configuration
            "vm.gas_limit" => config.vm.gas_limit = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid number: {}", e)))?,
            "vm.gas_price" => config.vm.gas_price = value.parse()
                .map_err(|e| AevorError::config(format!("Invalid number: {}", e)))?,

            // Other configuration values
            _ => return Err(AevorError::config(format!("Unknown configuration key: {}", key))),
        }
    }
    
    Ok(())
}

/// Interactive configuration setup
pub fn interactive_config_setup() -> Result<AevorConfig> {
    use super::prompt;
    use colored::Colorize;
    
    display::section("Aevor Configuration Setup");
    display::info("Let's set up your Aevor node configuration.");
    println!();
    
    // Start with default configuration
    let mut config = AevorConfig::default();
    
    // Node settings
    display::section("Node Settings");
    
    // Node name
    let node_name = prompt::input("Node name", Some(config.node.name.clone()))?;
    config.node.name = node_name;
    
    // Validator mode
    let is_validator = prompt::confirm("Run as a validator node?")?;
    config.node.is_validator = is_validator;
    
    // Network settings
    display::section("Network Settings");
    
    // Listen address
    let listen_addr = prompt::input("Listen address", Some(config.network.listen_addr.clone()))?;
    config.network.listen_addr = listen_addr;
    
    // P2P port
    let p2p_port = prompt::numeric_input("P2P port", Some(1024u16), Some(65535u16), Some(config.network.p2p_port))?;
    config.network.p2p_port = p2p_port;
    
    // UPnP
    let enable_upnp = prompt::confirm("Enable UPnP for port forwarding?")?;
    config.network.enable_upnp = enable_upnp;
    
    // API settings
    display::section("API Settings");
    
    // HTTP API
    let http_enabled = prompt::confirm("Enable HTTP API?")?;
    config.api.http_enabled = http_enabled;
    
    if http_enabled {
        let http_port = prompt::numeric_input("HTTP API port", Some(1024u16), Some(65535u16), Some(config.api.http_port))?;
        config.api.http_port = http_port;
    }
    
    // WebSocket API
    let ws_enabled = prompt::confirm("Enable WebSocket API?")?;
    config.api.ws_enabled = ws_enabled;
    
    if ws_enabled {
        let ws_port = prompt::numeric_input("WebSocket API port", Some(1024u16), Some(65535u16), Some(config.api.ws_port))?;
        config.api.ws_port = ws_port;
    }
    
    // Advanced settings
    let configure_advanced = prompt::confirm("Configure advanced settings?")?;
    
    if configure_advanced {
        // Storage settings
        display::section("Storage Settings");
        
        let storage_engines = ["rocksdb", "sled"];
        let storage_engine = prompt::select("Storage engine", &storage_engines)?;
        config.storage.engine = storage_engine.to_string();
        
        // Consensus settings
        display::section("Consensus Settings");
        
        // TEE
        let use_tee = prompt::confirm("Use Trusted Execution Environment (TEE)?")?;
        config.consensus.pou.use_tee = use_tee;
        
        if use_tee {
            let tee_types = ["simulation", "sgx", "sev", "trustzone"];
            let tee_type = prompt::select("TEE type", &tee_types)?;
            config.consensus.pou.tee_type = tee_type.to_string();
        }
        
        // Security accelerator
        let enable_accelerator = prompt::confirm("Enable Security Level Accelerator?")?;
        config.consensus.security_accelerator.enabled = enable_accelerator;
    }
    
    // Configuration summary
    display::section("Configuration Summary");
    
    println!("{}: {}", "Node name".blue().bold(), config.node.name);
    println!("{}: {}", "Validator mode".blue().bold(), if config.node.is_validator { "Yes".green() } else { "No".yellow() });
    println!("{}: {}:{}", "Network".blue().bold(), config.network.listen_addr, config.network.p2p_port);
    println!("{}: {}", "HTTP API".blue().bold(), if config.api.http_enabled { format!("Enabled (port {})", config.api.http_port).green() } else { "Disabled".red() });
    println!("{}: {}", "WebSocket API".blue().bold(), if config.api.ws_enabled { format!("Enabled (port {})", config.api.ws_port).green() } else { "Disabled".red() });
    println!("{}: {}", "Storage engine".blue().bold(), config.storage.engine);
    println!("{}: {}", "TEE".blue().bold(), if config.consensus.pou.use_tee { format!("Enabled ({})", config.consensus.pou.tee_type).green() } else { "Disabled".red() });
    println!("{}: {}", "Security Accelerator".blue().bold(), if config.consensus.security_accelerator.enabled { "Enabled".green() } else { "Disabled".red() });
    
    println!();
    let save_config = prompt::confirm("Save this configuration?")?;
    
    if save_config {
        let config_path = get_default_config_path();
        config.save(&config_path)?;
        display::success(&format!("Configuration saved to {}", config_path.display()));
    } else {
        display::warning("Configuration not saved.");
    }
    
    Ok(config)
}

/// Print configuration summary
pub fn print_config_summary(config: &AevorConfig) {
    use colored::Colorize;
    
    display::section("Configuration Summary");
    
    println!("{}: {}", "Node name".blue().bold(), config.node.name);
    println!("{}: {}", "Validator mode".blue().bold(), if config.node.is_validator { "Yes".green() } else { "No".yellow() });
    println!("{}: {}:{}", "Network".blue().bold(), config.network.listen_addr, config.network.p2p_port);
    println!("{}: {}", "HTTP API".blue().bold(), if config.api.http_enabled { format!("Enabled (port {})", config.api.http_port).green() } else { "Disabled".red() });
    println!("{}: {}", "WebSocket API".blue().bold(), if config.api.ws_enabled { format!("Enabled (port {})", config.api.ws_port).green() } else { "Disabled".red() });
    println!("{}: {}", "TEE".blue().bold(), if config.consensus.pou.use_tee { format!("Enabled ({})", config.consensus.pou.tee_type).green() } else { "Disabled".red() });
    println!("{}: {}", "Security Accelerator".blue().bold(), if config.consensus.security_accelerator.enabled { "Enabled".green() } else { "Disabled".red() });
    println!("{}: {}", "Storage engine".blue().bold(), config.storage.engine);
    
    if config.node.is_validator {
        println!();
        println!("{}", "Validator Settings".underline().bold());
        
        println!("{}: {}", "Block production rate".blue().bold(), format!("{}%", config.consensus.validator.block_production_rate));
        println!("{}: {}", "Commission rate".blue().bold(), format!("{:.2}%", config.consensus.validator.commission_rate as f64 / 100.0));
        println!("{}: {}", "Max parallel validations".blue().bold(), config.consensus.validator.max_parallel_validations);
    }
}
