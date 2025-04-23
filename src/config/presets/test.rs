use std::path::PathBuf;
use tempfile::tempdir;

use crate::config::{
    AevorConfig, ApiConfig, CompactionConfig, ConsensusConfig, DatabaseConfig, DiscoveryConfig,
    DualDagConfig, ExecutionConfig, FinalityConfig, MacroDagConfig, MicroDagConfig, NetworkConfig,
    NodeConfig, PoUConfig, PruningConfig, SecurityAcceleratorConfig, StorageConfig, ValidatorConfig,
    VmConfig,
};

/// Creates a test configuration preset
/// This configuration is optimized for unit and integration tests
pub fn config() -> AevorConfig {
    // Get a temporary directory for test data
    let temp_dir = tempdir().unwrap_or_else(|_| panic!("Failed to create temporary directory"));
    let temp_path = temp_dir.path().to_path_buf();
    let db_path = temp_dir.path().join("db");
    
    AevorConfig {
        node: NodeConfig {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Aevor Test Node".to_string(),
            is_validator: true, // Tests run as validators by default
            data_dir: temp_path,
            log_level: "warn".to_string(), // Minimal logging in tests
            max_memory_mb: 512, // Limited resources for tests
            worker_threads: 1, // Single thread for deterministic tests
            metrics_enabled: false, // No metrics in tests
            metrics_interval_seconds: 60,
            profiling_enabled: false,
        },
        consensus: ConsensusConfig {
            pou: PoUConfig {
                use_tee: false, // Simulated TEE in tests
                tee_type: "simulation".to_string(),
                corruption_check_interval_ms: 5000, // 5 seconds
                max_uncorrupted_chains: 3,
                auto_recovery_enabled: true,
                max_recovery_attempts: 2,
            },
            security_accelerator: SecurityAcceleratorConfig {
                enabled: true,
                minimal_security_validators_pct: 1,
                basic_security_validators_pct: 10,
                strong_security_validators_pct: 20,
                full_security_validators_pct: 30, // Lower thresholds for faster tests
                use_bls_aggregation: true,
                topology_aware_solicitation: false, // Simplified for tests
                validation_timeout_ms: 100, // Fast timeouts
            },
            dual_dag: DualDagConfig {
                micro_dag: MicroDagConfig {
                    max_transactions: 1000, // Small capacity for tests
                    max_dependencies_per_tx: 10,
                    enable_superposition: true,
                    max_potential_states: 3,
                    enable_speculative_execution: true,
                    max_speculative_depth: 2,
                },
                macro_dag: MacroDagConfig {
                    max_parents_per_block: 3,
                    max_block_size: 64 * 1024, // 64 KB
                    target_block_time_ms: 100, // Fast blocks for tests
                    max_transactions_per_block: 100,
                    dynamic_block_sizing: false, // Fixed size for deterministic tests
                },
            },
            validator: ValidatorConfig {
                key_path: temp_dir.path().join("validator_key_test.json"),
                stake_amount: 1000,
                commission_rate: 10,
                block_production_rate: 100,
                max_parallel_validations: 10,
            },
            min_validators: 1, // Single validator for tests
            validation_threshold: 51,
            finality: FinalityConfig {
                min_confirmations: 1,
                confirmation_percentage: 51,
                check_interval_ms: 50,
            },
        },
        network: NetworkConfig {
            listen_addr: "127.0.0.1".to_string(),
            p2p_port: 0, // Random port for tests
            enable_upnp: false,
            bootstrap_nodes: vec![], // No bootstrap nodes for tests
            max_peers: 5,
            target_outbound_peers: 1,
            connection_timeout_secs: 5,
            discovery: DiscoveryConfig {
                enabled: false, // No discovery in tests
                method: "none".to_string(),
                interval_secs: 10,
                max_discovered_peers: 10,
                prefer_validators: true,
            },
            topology_optimization: false, // Disabled for tests
            topology_optimization_interval_secs: 30,
            enable_rdma_transport: false,
            enable_erasure_coding: false, // Simplified for tests
            erasure_coding_shard_count: 3,
            erasure_coding_total_count: 5,
        },
        storage: StorageConfig {
            engine: "memory".to_string(), // In-memory database for tests
            db_path: db_path,
            create_if_missing: true,
            compression_enabled: false, // No compression for faster tests
            cache_size_mb: 64,
            max_open_files: 100,
            write_buffer_size: 8 * 1024 * 1024, // 8 MB
            compaction: CompactionConfig {
                enabled: false, // No compaction for tests
                style: "level".to_string(),
                interval_secs: 3600,
            },
            pruning: PruningConfig {
                enabled: false, // No pruning for tests
                interval_secs: 3600,
                keep_latest_blocks: 100,
                keep_finalized_blocks: true,
                keep_state_blocks: 50,
            },
        },
        api: ApiConfig {
            http_enabled: false, // Disabled by default in tests
            http_addr: "127.0.0.1".to_string(),
            http_port: 0, // Random port for tests
            ws_enabled: false,
            ws_port: 0,
            jsonrpc_enabled: false,
            jsonrpc_port: 0,
            cors_enabled: false,
            cors_allowed_origins: vec![],
            rate_limit_enabled: false,
            rate_limit_requests_per_min: 0,
            auth_enabled: false,
            api_keys: vec![],
        },
        vm: VmConfig {
            max_memory_bytes: 32 * 1024 * 1024, // 32 MB
            max_execution_time_ms: 1000, // 1 second
            gas_limit: 1_000_000,
            gas_price: 1,
            gas_metering_enabled: true,
            debug_enabled: true, // Enable debugging in tests
            jit_enabled: false, // Disable JIT for deterministic tests
            max_contract_size: 128 * 1024, // 128 KB
            max_function_name_length: 256,
            max_parameter_count: 32,
            max_call_depth: 5,
        },
        execution: ExecutionConfig {
            max_gas_per_tx: 1_000_000,
            gas_price: 1,
            max_execution_time_ms: 1000,
            max_memory_mb: 32,
            use_tee: false, // Simulated TEE in tests
            enable_superposition: true,
            max_superpositioned_objects: 100,
            max_parallel_execution: 4,
        },
    }
}

/// Creates a minimal test configuration with bare minimum settings
pub fn minimal() -> AevorConfig {
    let mut config = config();
    
    // Minimal settings for node
    config.node.worker_threads = 1;
    config.node.max_memory_mb = 256;
    
    // Minimal consensus settings
    config.consensus.min_validators = 1;
    config.consensus.dual_dag.micro_dag.max_transactions = 100;
    config.consensus.dual_dag.micro_dag.enable_superposition = false;
    config.consensus.dual_dag.macro_dag.max_transactions_per_block = 10;
    
    // Minimal network settings
    config.network.max_peers = 1;
    config.network.target_outbound_peers = 1;
    
    // Minimal execution settings
    config.execution.max_parallel_execution = 1;
    config.execution.enable_superposition = false;
    
    config
}

/// Creates a test configuration optimized for integration tests with multiple nodes
pub fn multi_node() -> AevorConfig {
    let mut config = config();
    
    // Configure for multi-node tests
    config.node.worker_threads = 2;
    
    // Network settings for multiple nodes
    config.network.listen_addr = "127.0.0.1".to_string();
    config.network.discovery.enabled = true;
    config.network.discovery.method = "static".to_string();
    config.network.max_peers = 10;
    config.network.target_outbound_peers = 3;
    
    // Consensus settings for multiple validators
    config.consensus.min_validators = 3;
    config.consensus.finality.min_confirmations = 2;
    
    config
}

/// Creates a test configuration for benchmarking
pub fn benchmark() -> AevorConfig {
    let mut config = config();
    
    // Higher resource limits for benchmarks
    config.node.worker_threads = 8;
    config.node.max_memory_mb = 4096;
    
    // Faster consensus settings
    config.consensus.pou.corruption_check_interval_ms = 1000;
    config.consensus.finality.check_interval_ms = 10;
    
    // Higher limits for benchmarking
    config.consensus.dual_dag.micro_dag.max_transactions = 100_000;
    config.consensus.dual_dag.macro_dag.max_transactions_per_block = 1000;
    
    // Optimized storage settings
    config.storage.cache_size_mb = 1024;
    config.storage.write_buffer_size = 128 * 1024 * 1024; // 128 MB
    
    // More execution parallelism
    config.execution.max_parallel_execution = 16;
    
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_test_config() {
        let config = config();
        
        // Verify test-specific settings
        assert_eq!(config.node.log_level, "warn");
        assert_eq!(config.node.worker_threads, 1);
        assert!(config.node.is_validator);
        assert!(!config.node.metrics_enabled);
        
        // Verify consensus settings
        assert!(!config.consensus.pou.use_tee);
        assert!(config.consensus.security_accelerator.enabled);
        
        // Verify storage settings
        assert_eq!(config.storage.engine, "memory");
        assert!(!config.storage.compression_enabled);
        assert!(!config.storage.compaction.enabled);
        assert!(!config.storage.pruning.enabled);
        
        // Verify API settings
        assert!(!config.api.http_enabled);
    }
    
    #[test]
    fn test_minimal_config() {
        let config = minimal();
        
        assert_eq!(config.node.worker_threads, 1);
        assert_eq!(config.node.max_memory_mb, 256);
        assert!(!config.consensus.dual_dag.micro_dag.enable_superposition);
        assert!(!config.execution.enable_superposition);
    }
    
    #[test]
    fn test_multi_node_config() {
        let config = multi_node();
        
        assert_eq!(config.node.worker_threads, 2);
        assert!(config.network.discovery.enabled);
        assert_eq!(config.consensus.min_validators, 3);
    }
    
    #[test]
    fn test_benchmark_config() {
        let config = benchmark();
        
        assert_eq!(config.node.worker_threads, 8);
        assert_eq!(config.node.max_memory_mb, 4096);
        assert_eq!(config.execution.max_parallel_execution, 16);
    }
}
