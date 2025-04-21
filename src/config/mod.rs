use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{AevorError, Result};

/// Top-level configuration for the Aevor blockchain application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AevorConfig {
    /// Node-specific settings
    pub node: NodeConfig,
    
    /// Consensus configuration
    pub consensus: ConsensusConfig,
    
    /// Network configuration
    pub network: NetworkConfig,
    
    /// Storage configuration
    pub storage: StorageConfig,
    
    /// API configuration
    pub api: ApiConfig,
    
    /// Virtual machine configuration
    pub vm: VmConfig,
    
    /// Execution configuration
    pub execution: ExecutionConfig,
}

/// Configuration for node-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node identifier
    pub id: String,
    
    /// Node name (human-readable)
    pub name: String,
    
    /// Whether this node is a validator
    pub is_validator: bool,
    
    /// The node's data directory
    pub data_dir: PathBuf,
    
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
    
    /// Maximum memory usage in megabytes
    pub max_memory_mb: usize,
    
    /// Number of worker threads (0 = use number of CPU cores)
    pub worker_threads: usize,
    
    /// Enable metrics collection
    pub metrics_enabled: bool,
    
    /// Metrics collection interval in seconds
    pub metrics_interval_seconds: u64,
    
    /// Enable profiling (for development)
    pub profiling_enabled: bool,
}

/// Configuration for consensus mechanisms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Proof of Uncorruption configuration
    pub pou: PoUConfig,
    
    /// Security Level Accelerator configuration
    pub security_accelerator: SecurityAcceleratorConfig,
    
    /// Dual-DAG configuration
    pub dual_dag: DualDagConfig,
    
    /// Validator configuration (if this node is a validator)
    pub validator: ValidatorConfig,
    
    /// Minimum number of validators required
    pub min_validators: usize,
    
    /// Validation threshold percentage (0-100)
    pub validation_threshold: u8,
    
    /// Block finality configuration
    pub finality: FinalityConfig,
}

/// Configuration for Proof of Uncorruption (PoU)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoUConfig {
    /// Enable TEE (Trusted Execution Environment)
    pub use_tee: bool,
    
    /// TEE type (sgx, sev, trustzone, simulation)
    pub tee_type: String,
    
    /// Corruption detection interval in milliseconds
    pub corruption_check_interval_ms: u64,
    
    /// Maximum number of uncorrupted chains to track
    pub max_uncorrupted_chains: usize,
    
    /// Enable automatic recovery from corruption
    pub auto_recovery_enabled: bool,
    
    /// Maximum recovery attempts
    pub max_recovery_attempts: usize,
}

/// Configuration for Security Level Accelerator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAcceleratorConfig {
    /// Enable Security Level Accelerator
    pub enabled: bool,
    
    /// Minimal security validator percentage (0-100)
    pub minimal_security_validators_pct: u8,
    
    /// Basic security validator percentage (0-100)
    pub basic_security_validators_pct: u8,
    
    /// Strong security validator percentage (0-100)
    pub strong_security_validators_pct: u8,
    
    /// Full security validator percentage (0-100)
    pub full_security_validators_pct: u8,
    
    /// Use BLS signature aggregation
    pub use_bls_aggregation: bool,
    
    /// Enable topology-aware validation solicitation
    pub topology_aware_solicitation: bool,
    
    /// Validation timeout in milliseconds
    pub validation_timeout_ms: u64,
}

/// Configuration for Dual-DAG architecture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualDagConfig {
    /// Micro-DAG configuration
    pub micro_dag: MicroDagConfig,
    
    /// Macro-DAG configuration
    pub macro_dag: MacroDagConfig,
}

/// Configuration for Micro-DAG (transaction dependency graph)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroDagConfig {
    /// Maximum number of transactions in the micro-DAG
    pub max_transactions: usize,
    
    /// Maximum number of dependencies per transaction
    pub max_dependencies_per_tx: usize,
    
    /// Enable transaction superposition
    pub enable_superposition: bool,
    
    /// Maximum number of potential states per transaction
    pub max_potential_states: usize,
    
    /// Enable speculative execution
    pub enable_speculative_execution: bool,
    
    /// Maximum speculative execution depth
    pub max_speculative_depth: usize,
}

/// Configuration for Macro-DAG (block reference graph)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroDagConfig {
    /// Maximum number of parent references per block
    pub max_parents_per_block: usize,
    
    /// Maximum block size in bytes
    pub max_block_size: usize,
    
    /// Target time between blocks in milliseconds
    pub target_block_time_ms: u64,
    
    /// Maximum transactions per block
    pub max_transactions_per_block: usize,
    
    /// Enable dynamic block sizing
    pub dynamic_block_sizing: bool,
}

/// Configuration for validator operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    /// Path to validator key file
    pub key_path: PathBuf,
    
    /// Validator stake amount
    pub stake_amount: u64,
    
    /// Validator commission rate (0-100)
    pub commission_rate: u8,
    
    /// Block production rate limiting (0-100)
    /// (percentage of blocks this validator should produce)
    pub block_production_rate: u8,
    
    /// Maximum parallel validations
    pub max_parallel_validations: usize,
}

/// Configuration for block finality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityConfig {
    /// Minimum confirmations required for finality
    pub min_confirmations: usize,
    
    /// Confirmation percentage required (0-100)
    pub confirmation_percentage: u8,
    
    /// Finality check interval in milliseconds
    pub check_interval_ms: u64,
}

/// Configuration for the networking layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Listen IP address
    pub listen_addr: String,
    
    /// P2P port
    pub p2p_port: u16,
    
    /// Enable UPnP for port forwarding
    pub enable_upnp: bool,
    
    /// Bootstrap nodes (peer addresses)
    pub bootstrap_nodes: Vec<String>,
    
    /// Maximum number of peers
    pub max_peers: usize,
    
    /// Target number of outbound connections
    pub target_outbound_peers: usize,
    
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    
    /// Peer discovery configuration
    pub discovery: DiscoveryConfig,
    
    /// Enable topology optimization
    pub topology_optimization: bool,
    
    /// Topology optimization interval in seconds
    pub topology_optimization_interval_secs: u64,
    
    /// Enable RDMA-style transport
    pub enable_rdma_transport: bool,
    
    /// Enable erasure coding for data availability
    pub enable_erasure_coding: bool,
    
    /// Erasure coding shard count (K in K-of-N)
    pub erasure_coding_shard_count: usize,
    
    /// Erasure coding total count (N in K-of-N)
    pub erasure_coding_total_count: usize,
}

/// Configuration for peer discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable peer discovery
    pub enabled: bool,
    
    /// Discovery method (kademlia, mdns, etc.)
    pub method: String,
    
    /// Discovery interval in seconds
    pub interval_secs: u64,
    
    /// Maximum number of discovered peers to store
    pub max_discovered_peers: usize,
    
    /// Prefer validators during discovery
    pub prefer_validators: bool,
}

/// Configuration for the storage subsystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage engine (rocksdb, sled)
    pub engine: String,
    
    /// Database path
    pub db_path: PathBuf,
    
    /// Create database if it doesn't exist
    pub create_if_missing: bool,
    
    /// Enable compression
    pub compression_enabled: bool,
    
    /// Cache size in megabytes
    pub cache_size_mb: usize,
    
    /// Maximum open files
    pub max_open_files: i32,
    
    /// Write buffer size in bytes
    pub write_buffer_size: usize,
    
    /// Database compaction settings
    pub compaction: CompactionConfig,
    
    /// Pruning configuration
    pub pruning: PruningConfig,
}

/// Configuration for database compaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionConfig {
    /// Enable periodic compaction
    pub enabled: bool,
    
    /// Compaction style (level, universal)
    pub style: String,
    
    /// Compaction interval in seconds
    pub interval_secs: u64,
}

/// Configuration for database pruning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningConfig {
    /// Enable pruning
    pub enabled: bool,
    
    /// Pruning interval in seconds
    pub interval_secs: u64,
    
    /// Keep the latest N blocks
    pub keep_latest_blocks: u64,
    
    /// Keep blocks with finality
    pub keep_finalized_blocks: bool,
    
    /// Keep state from the latest N blocks
    pub keep_state_blocks: u64,
}

/// Configuration for the API layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Enable HTTP API
    pub http_enabled: bool,
    
    /// HTTP API listen address
    pub http_addr: String,
    
    /// HTTP API port
    pub http_port: u16,
    
    /// Enable WebSocket API
    pub ws_enabled: bool,
    
    /// WebSocket API port
    pub ws_port: u16,
    
    /// Enable JSON-RPC API
    pub jsonrpc_enabled: bool,
    
    /// JSON-RPC API port
    pub jsonrpc_port: u16,
    
    /// Enable CORS
    pub cors_enabled: bool,
    
    /// CORS allowed origins
    pub cors_allowed_origins: Vec<String>,
    
    /// Enable rate limiting
    pub rate_limit_enabled: bool,
    
    /// Rate limit in requests per minute
    pub rate_limit_requests_per_min: u32,
    
    /// Enable API authentication
    pub auth_enabled: bool,
    
    /// API keys (for authenticated endpoints)
    pub api_keys: Vec<String>,
}

/// Configuration for the virtual machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Maximum memory usage in bytes
    pub max_memory_bytes: usize,
    
    /// Maximum execution time in milliseconds
    pub max_execution_time_ms: u64,
    
    /// Gas limit for VM execution
    pub gas_limit: u64,
    
    /// Gas price in nano tokens
    pub gas_price: u64,
    
    /// Enable gas metering
    pub gas_metering_enabled: bool,
    
    /// Enable debugging
    pub debug_enabled: bool,
    
    /// Enable JIT compilation
    pub jit_enabled: bool,
    
    /// Maximum contract size in bytes
    pub max_contract_size: usize,
    
    /// Maximum function name length
    pub max_function_name_length: usize,
    
    /// Maximum parameter count
    pub max_parameter_count: usize,
    
    /// Maximum call depth
    pub max_call_depth: usize,
}

/// Configuration for the execution engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    /// Maximum gas per transaction
    pub max_gas_per_tx: u64,
    
    /// Gas price in smallest unit
    pub gas_price: u64,
    
    /// Maximum execution time per transaction in milliseconds
    pub max_execution_time_ms: u64,
    
    /// Maximum memory usage per transaction in megabytes
    pub max_memory_mb: usize,
    
    /// Use TEE for execution
    pub use_tee: bool,
    
    /// Enable superposition
    pub enable_superposition: bool,
    
    /// Maximum objects in superposition
    pub max_superpositioned_objects: usize,
    
    /// Maximum parallel execution threads
    pub max_parallel_execution: usize,
}

impl AevorConfig {
    /// Load configuration from a JSON file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|e| AevorError::config(format!("Failed to read config file: {}", e)))?;
        
        serde_json::from_str(&contents)
            .map_err(|e| AevorError::config(format!("Failed to parse config file: {}", e)))
    }
    
    /// Save configuration to a JSON file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| AevorError::config(format!("Failed to serialize config: {}", e)))?;
        
        fs::write(path, contents)
            .map_err(|e| AevorError::config(format!("Failed to write config file: {}", e)))
    }
    
    /// Load configuration from a file or create a default one if the file doesn't exist
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Result<Self> {
        if path.as_ref().exists() {
            Self::load(path)
        } else {
            let config = Self::default();
            config.save(&path)?;
            Ok(config)
        }
    }
    
    /// Convert duration in milliseconds to Duration
    pub fn ms_to_duration(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }
}

impl Default for AevorConfig {
    fn default() -> Self {
        AevorConfig {
            node: NodeConfig {
                id: uuid::Uuid::new_v4().to_string(),
                name: "Aevor Node".to_string(),
                is_validator: false,
                data_dir: PathBuf::from("./data"),
                log_level: "info".to_string(),
                max_memory_mb: 4096,
                worker_threads: 0,
                metrics_enabled: true,
                metrics_interval_seconds: 60,
                profiling_enabled: false,
            },
            consensus: ConsensusConfig {
                pou: PoUConfig {
                    use_tee: true,
                    tee_type: "simulation".to_string(),
                    corruption_check_interval_ms: 30000,
                    max_uncorrupted_chains: 10,
                    auto_recovery_enabled: true,
                    max_recovery_attempts: 5,
                },
                security_accelerator: SecurityAcceleratorConfig {
                    enabled: true,
                    minimal_security_validators_pct: 1,
                    basic_security_validators_pct: 15,
                    strong_security_validators_pct: 34,
                    full_security_validators_pct: 67,
                    use_bls_aggregation: true,
                    topology_aware_solicitation: true,
                    validation_timeout_ms: 1000,
                },
                dual_dag: DualDagConfig {
                    micro_dag: MicroDagConfig {
                        max_transactions: 1_000_000,
                        max_dependencies_per_tx: 100,
                        enable_superposition: true,
                        max_potential_states: 10,
                        enable_speculative_execution: true,
                        max_speculative_depth: 5,
                    },
                    macro_dag: MacroDagConfig {
                        max_parents_per_block: 10,
                        max_block_size: 2 * 1024 * 1024, // 2 MB
                        target_block_time_ms: 500,
                        max_transactions_per_block: 10000,
                        dynamic_block_sizing: true,
                    },
                },
                validator: ValidatorConfig {
                    key_path: PathBuf::from("./validator_key.json"),
                    stake_amount: 1000000,
                    commission_rate: 10,
                    block_production_rate: 100,
                    max_parallel_validations: 100,
                },
                min_validators: 4,
                validation_threshold: 67,
                finality: FinalityConfig {
                    min_confirmations: 4,
                    confirmation_percentage: 67,
                    check_interval_ms: 100,
                },
            },
            network: NetworkConfig {
                listen_addr: "127.0.0.1".to_string(),
                p2p_port: 7777,
                enable_upnp: false,
                bootstrap_nodes: vec![],
                max_peers: 50,
                target_outbound_peers: 10,
                connection_timeout_secs: 30,
                discovery: DiscoveryConfig {
                    enabled: true,
                    method: "kademlia".to_string(),
                    interval_secs: 60,
                    max_discovered_peers: 1000,
                    prefer_validators: true,
                },
                topology_optimization: true,
                topology_optimization_interval_secs: 300,
                enable_rdma_transport: true,
                enable_erasure_coding: true,
                erasure_coding_shard_count: 10,
                erasure_coding_total_count: 16,
            },
            storage: StorageConfig {
                engine: "rocksdb".to_string(),
                db_path: PathBuf::from("./data/db"),
                create_if_missing: true,
                compression_enabled: true,
                cache_size_mb: 512,
                max_open_files: 1000,
                write_buffer_size: 64 * 1024 * 1024, // 64 MB
                compaction: CompactionConfig {
                    enabled: true,
                    style: "level".to_string(),
                    interval_secs: 3600,
                },
                pruning: PruningConfig {
                    enabled: true,
                    interval_secs: 3600,
                    keep_latest_blocks: 10000,
                    keep_finalized_blocks: true,
                    keep_state_blocks: 1000,
                },
            },
            api: ApiConfig {
                http_enabled: true,
                http_addr: "127.0.0.1".to_string(),
                http_port: 8080,
                ws_enabled: true,
                ws_port: 8081,
                jsonrpc_enabled: true,
                jsonrpc_port: 8082,
                cors_enabled: true,
                cors_allowed_origins: vec!["*".to_string()],
                rate_limit_enabled: true,
                rate_limit_requests_per_min: 600,
                auth_enabled: false,
                api_keys: vec![],
            },
            vm: VmConfig {
                max_memory_bytes: 128 * 1024 * 1024, // 128 MB
                max_execution_time_ms: 5000,
                gas_limit: 10_000_000,
                gas_price: 1,
                gas_metering_enabled: true,
                debug_enabled: false,
                jit_enabled: true,
                max_contract_size: 1024 * 1024, // 1 MB
                max_function_name_length: 256,
                max_parameter_count: 32,
                max_call_depth: 10,
            },
            execution: ExecutionConfig {
                max_gas_per_tx: 10_000_000,
                gas_price: 1,
                max_execution_time_ms: 5000,
                max_memory_mb: 128,
                use_tee: true,
                enable_superposition: true,
                max_superpositioned_objects: 1000,
                max_parallel_execution: 32,
            },
        }
    }
}

/// Module containing configuration presets
pub mod presets;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let config = AevorConfig::default();
        assert_eq!(config.node.log_level, "info");
        assert_eq!(config.consensus.dual_dag.micro_dag.max_transactions, 1_000_000);
        assert_eq!(config.consensus.security_accelerator.enabled, true);
    }

    #[test]
    fn test_save_and_load_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        
        let config = AevorConfig::default();
        config.save(&config_path).unwrap();
        
        let loaded_config = AevorConfig::load(&config_path).unwrap();
        assert_eq!(loaded_config.node.log_level, config.node.log_level);
        assert_eq!(loaded_config.consensus.dual_dag.micro_dag.max_transactions, config.consensus.dual_dag.micro_dag.max_transactions);
    }

    #[test]
    fn test_load_or_default() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("nonexistent_config.json");
        
        let config = AevorConfig::load_or_default(&config_path).unwrap();
        assert_eq!(config.node.log_level, "info");
        
        // The file should have been created
        assert!(config_path.exists());
    }

    #[test]
    fn test_load_invalid_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("invalid_config.json");
        
        // Create an invalid JSON file
        let mut file = fs::File::create(&config_path).unwrap();
        file.write_all(b"{invalid json}").unwrap();
        
        let result = AevorConfig::load(&config_path);
        assert!(result.is_err());
    }
}
