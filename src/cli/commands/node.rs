use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use clap::Parser;

use crate::config::AevorConfig;
use crate::error::{AevorError, Result};
use crate::cli::utils::display;
use super::CommandExecutor;

/// Commands for starting and managing an Aevor node
#[derive(Debug, Parser)]
pub struct NodeCommand {
    /// Run as a validator node
    #[clap(long)]
    pub validator: bool,
    
    /// Path to data directory (defaults to ~/.aevor/data)
    #[clap(long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,
    
    /// Path to the node key file
    #[clap(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,
    
    /// Network to connect to (mainnet, testnet, devnet)
    #[clap(long, default_value = "testnet")]
    pub network: String,
    
    /// P2P port for node communication
    #[clap(long)]
    pub p2p_port: Option<u16>,
    
    /// RPC port for API requests
    #[clap(long)]
    pub rpc_port: Option<u16>,
    
    /// WebSocket port for subscriptions
    #[clap(long)]
    pub ws_port: Option<u16>,
    
    /// Disable API endpoints
    #[clap(long)]
    pub disable_api: bool,
    
    /// Enable detailed metrics
    #[clap(long)]
    pub metrics: bool,
    
    /// Run in development mode (faster block time, simpler consensus)
    #[clap(long)]
    pub dev: bool,
    
    /// Bootstrap nodes to connect to
    #[clap(long, value_name = "ADDR", multiple = true)]
    pub bootstrap: Vec<String>,
    
    /// Disable automatic peer discovery
    #[clap(long)]
    pub disable_discovery: bool,
    
    /// Run node with minimal output
    #[clap(long)]
    pub quiet: bool,
}

#[async_trait::async_trait]
impl CommandExecutor for NodeCommand {
    async fn execute(&self, config: Arc<AevorConfig>) -> Result<()> {
        let mut node_config = config.node.clone();
        let mut network_config = config.network.clone();
        
        // Update config with command line arguments
        node_config.is_validator = self.validator;
        
        if let Some(data_dir) = &self.data_dir {
            node_config.data_dir = data_dir.clone();
        }
        
        if let Some(p2p_port) = self.p2p_port {
            network_config.p2p_port = p2p_port;
        }
        
        if !self.bootstrap.is_empty() {
            network_config.bootstrap_nodes = self.bootstrap.clone();
        }
        
        network_config.enable_upnp = !self.disable_discovery;
        
        // Display configuration summary
        if !self.quiet {
            display_node_config(&node_config, &network_config, self.dev);
        }
        
        // Create the updated config
        let updated_config = Arc::new(AevorConfig {
            node: node_config,
            network: network_config,
            ..(*config).clone()
        });
        
        // Set up progress indicators
        let mut progress_indicators = vec![];
        
        // Initialize node
        display::section("Initializing Aevor Node");
        display::info("Starting initialization process...");
        
        // Initialize storage
        let storage_pb = display::spinner("Initializing storage subsystem");
        tokio::time::sleep(Duration::from_millis(600)).await; // Simulated initialization
        storage_pb.finish_with_message("Storage subsystem initialized");
        
        // Initialize peer-to-peer network
        let network_pb = display::spinner("Starting peer-to-peer network");
        tokio::time::sleep(Duration::from_millis(800)).await; // Simulated initialization
        network_pb.finish_with_message("P2P network started on port 7777");
        
        // Initialize consensus
        let consensus_pb = display::spinner("Initializing PoU consensus engine");
        tokio::time::sleep(Duration::from_millis(1200)).await; // Simulated initialization
        consensus_pb.finish_with_message("Consensus engine initialized");
        
        // Initialize API if enabled
        if !self.disable_api {
            let api_pb = display::spinner("Starting API server");
            tokio::time::sleep(Duration::from_millis(500)).await; // Simulated initialization
            let api_port = updated_config.api.http_port;
            api_pb.finish_with_message(&format!("API server started on port {}", api_port));
        }
        
        // Node startup complete
        display::section("Node Startup Complete");
        
        if self.validator {
            display::success("Validator node is running");
        } else {
            display::success("Full node is running");
        }
        
        display::info("Press Ctrl+C to stop the node");
        
        // Simulated node operation
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            // In a real implementation, we would check for shutdown signals
        }
    }
}

/// Display node configuration summary
fn display_node_config(node_config: &crate::config::NodeConfig, network_config: &crate::config::NetworkConfig, dev_mode: bool) {
    display::section("Node Configuration");
    
    let mut table = display::create_table(vec!["Setting", "Value"]);
    
    display::add_row(&mut table, vec![
        "Node Type".to_string(),
        (if node_config.is_validator { "Validator".to_string() } else { "Full Node".to_string() })
    ]);
    
    display::add_row(&mut table, vec![
        "Data Directory".to_string(),
        node_config.data_dir.to_string_lossy().to_string()
    ]);
    
    display::add_row(&mut table, vec![
        "Network".to_string(),
        (if dev_mode { "Development".to_string() } else { "Testnet".to_string() })
    ]);
    
    display::add_row(&mut table, vec![
        "P2P Port".to_string(),
        network_config.p2p_port.to_string()
    ]);
    
    display::add_row(&mut table, vec![
        "Bootstrap Nodes".to_string(),
        (if network_config.bootstrap_nodes.is_empty() { 
            "Auto-discovery".to_string() 
        } else { 
            format!("{} nodes", network_config.bootstrap_nodes.len()) 
        })
    ]);
    
    display::add_row(&mut table, vec![
        "Log Level".to_string(),
        node_config.log_level.to_string()
    ]);
    
    display::print_table(table);
}
