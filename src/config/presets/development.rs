use std::path::PathBuf;

use crate::config::{
    AevorConfig, ApiConfig, CompactionConfig, ConsensusConfig, DatabaseConfig, DiscoveryConfig,
    DualDagConfig, ExecutionConfig, FinalityConfig, MacroDagConfig, MicroDagConfig, NetworkConfig,
    NodeConfig, PoUConfig, PruningConfig, SecurityAcceleratorConfig, StorageConfig, ValidatorConfig,
    VmConfig,
};

/// Creates a development configuration preset
pub fn config() -> AevorConfig {
    AevorConfig {
        node: NodeConfig {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Aevor Dev Node".to_string(),
            is_validator: true, // Default as validator in development
            data_dir: PathBuf::from("./data_dev"),
            log_level: "debug".to_string(), // More verbose logging for development
            max_memory_mb: 2048, // 2GB
            worker_threads: 0, // Auto-detect
            metrics_enabled: true,
            metrics_interval_seconds: 30, // More frequent metrics collection
            profiling_enabled: true, // Enable profiling in development
        },
        consensus: ConsensusConfig {
            pou: PoUConfig {
                use_tee: false, // Use simulated TEE in development
                tee_type: "simulation".to_string(),
                corruption_check_interval_ms: 10000, // 10 seconds
                max_uncorrupted_chains: 5,
                auto_recovery_enabled: true,
                max_recovery_attempts: 3,
            },
            security_accelerator: SecurityAcceleratorConfig {
                enabled: true,
                minimal_security_validators_pct: 1,
                basic_security_validators_pct: 10,
                strong_security_validators_pct: 25,
                full_security_validators_pct: 51,
                use_bls_aggregation: true,
                topology_aware_solicitation: true,
                validation_timeout_ms: 500,
            },
            dual_dag: DualDagConfig {
                micro_dag: MicroDagConfig {
                    max_transactions: 100_000,
                    max_dependencies_per_tx: 50,
                    enable_superposition: true,
                    max_potential_states: 5,
                    enable_speculative_execution: true,
                    max_speculative_depth: 3,
                },
                macro_dag: MacroDagConfig {
                    max_parents_per_block: 5,
                    max_block_size: 1 * 1024 * 1024, // 1 MB
                    target_block_time_ms: 250,
                    max_transactions_per_block: 5000,
                    dynamic_block_sizing: true,
                },
            },
            validator: ValidatorConfig {
                key_path: PathBuf::from("./validator_key_dev.json"),
                stake_amount: 100000,
                commission_rate: 10,
                block_production_rate: 100,
                max_parallel_validations: 50,
            },
            min_validators: 1, // Allow operation with a single validator in dev
            validation_threshold: 51,
            finality: FinalityConfig {
                min_confirmations: 1,
                confirmation_percentage: 51,
                check_interval_ms: 100,
            },
        },
        network: NetworkConfig {
            listen_addr: "127.0.0.1".to_string(),
            p2p_port: 7777,
            enable_upnp: false,
            bootstrap_nodes: vec!["127.0.0.1:7778".to_string()], // Local bootstrap node
            max_peers: 20,
            target_outbound_peers: 5,
            connection_timeout_secs: 10,
            discovery: DiscoveryConfig {
                enabled: true,
                method: "local".to_string(),
                interval_secs: 30,
                max_discovered_peers: 100,
                prefer_validators: true,
            },
            topology_optimization: true,
            topology_optimization_interval_secs: 60,
            enable_rdma_transport: false, // Simplified transport in development
            enable_erasure_coding: true,
            erasure_coding_shard_count: 5,
            erasure_coding_total_count: 8,
        },
        storage: StorageConfig {
            engine: "rocksdb".to_string(),
            db_path: PathBuf::from("./data_dev/db"),
            create_if_missing: true,
            compression_enabled: true,
            cache_size_mb: 256,
            max_open_files: 500,
            write_buffer_size: 32 * 1024 * 1024, // 32 MB
            compaction: CompactionConfig {
                enabled: true,
                style: "level".to_string(),
                interval_secs: 3600,
            },
            pruning: PruningConfig {
                enabled: true,
                interval_secs: 1800,
                keep_latest_blocks: 1000,
                keep_finalized_blocks: true,
                keep_state_blocks: 100,
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
            rate_limit_enabled: false, // No rate limiting in development
            rate_limit_requests_per_min: 0,
            auth_enabled: false,
            api_keys: vec![],
        },
        vm: VmConfig {
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            max_execution_time_ms: 5000,
            gas_limit: 10_000_000,
            gas_price: 1,
            gas_metering_enabled: true,
            debug_enabled: true, // Enable debugging in development
            jit_enabled: true,
            max_contract_size: 512 * 1024, // 512 KB
            max_function_name_length: 256,
            max_parameter_count: 32,
            max_call_depth: 10,
        },
        execution: ExecutionConfig {
            max_gas_per_tx: 10_000_000,
            gas_price: 1,
            max_execution_time_ms: 5000,
            max_memory_mb: 64,
            use_tee: false, // Use simulated TEE in development
            enable_superposition: true,
            max_superpositioned_objects: 500,
            max_parallel_execution: 16,
        },
    }
}

/// Creates a minimal development configuration preset
/// This configuration uses minimum resources and is suitable for
/// development on lower-end hardware or containerized environments
pub fn minimal() -> AevorConfig {
    let mut cfg = config();
    
    // Reduce resource usage
    cfg.node.max_memory_mb = 512;
    cfg.storage.cache_size_mb = 64;
    cfg.storage.max_open_files = 100;
    cfg.storage.write_buffer_size = 8 * 1024 * 1024; // 8 MB
    cfg.vm.max_memory_bytes = 32 * 1024 * 1024; // 32 MB
    cfg.execution.max_memory_mb = 32;
    cfg.execution.max_parallel_execution = 4;
    
    // Simplify consensus for minimal resource usage
    cfg.consensus.dual_dag.micro_dag.max_transactions = 10_000;
    cfg.consensus.dual_dag.micro_dag.max_potential_states = 2;
    cfg.consensus.dual_dag.macro_dag.max_block_size = 256 * 1024; // 256 KB
    cfg.consensus.dual_dag.macro_dag.max_transactions_per_block = 1000;
    
    // Reduce network activity
    cfg.network.max_peers = 5;
    cfg.network.target_outbound_peers = 2;
    
    cfg
}

/// Creates a local cluster development configuration preset
/// This configuration is optimized for running multiple nodes
/// in a local development cluster
pub fn local_cluster() -> AevorConfig {
    let mut cfg = config();
    
    // Each node would modify these parameters slightly
    // Here we just show the base configuration
    cfg.node.name = "Aevor Local Cluster Node".to_string();
    
    // Set up for multi-validator testing
    cfg.consensus.min_validators = 4;
    cfg.consensus.validation_threshold = 67; // 2/3 majority
    cfg.consensus.finality.min_confirmations = 3;
    
    // Network settings for local testing
    cfg.network.bootstrap_nodes = vec![
        "127.0.0.1:7771".to_string(),
        "127.0.0.1:7772".to_string(),
        "127.0.0.1:7773".to_string(),
        "127.0.0.1:7774".to_string(),
    ];
    
    // Ports would be set differently for each node instance
    // Here we just show the base port
    cfg.network.p2p_port = 7770;
    cfg.api.http_port = 8070;
    cfg.api.ws_port = 8071;
    cfg.api.jsonrpc_port = 8072;
    
    cfg
}
