use std::path::PathBuf;

use crate::config::{
    AevorConfig, ApiConfig, CompactionConfig, ConsensusConfig, DatabaseConfig, DiscoveryConfig,
    DualDagConfig, ExecutionConfig, FinalityConfig, MacroDagConfig, MicroDagConfig, NetworkConfig,
    NodeConfig, PoUConfig, PruningConfig, SecurityAcceleratorConfig, StorageConfig, ValidatorConfig,
    VmConfig,
};

/// Creates a standard production configuration preset
pub fn config() -> AevorConfig {
    AevorConfig {
        node: NodeConfig {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Aevor Node".to_string(),
            is_validator: false, // Non-validator by default in production
            data_dir: PathBuf::from("/var/lib/aevor"),
            log_level: "info".to_string(),
            max_memory_mb: 8192, // 8GB
            worker_threads: 0, // Auto-detect
            metrics_enabled: true,
            metrics_interval_seconds: 60,
            profiling_enabled: false, // Disabled in production
        },
        consensus: ConsensusConfig {
            pou: PoUConfig {
                use_tee: true, // Real TEE in production
                tee_type: "sgx".to_string(),
                corruption_check_interval_ms: 30000, // 30 seconds
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
                key_path: PathBuf::from("/etc/aevor/validator_key.json"),
                stake_amount: 1000000,
                commission_rate: 10,
                block_production_rate: 100,
                max_parallel_validations: 100,
            },
            min_validators: 4,
            validation_threshold: 67, // 2/3 majority
            finality: FinalityConfig {
                min_confirmations: 4,
                confirmation_percentage: 67,
                check_interval_ms: 100,
            },
        },
        network: NetworkConfig {
            listen_addr: "0.0.0.0".to_string(),
            p2p_port: 7777,
            enable_upnp: true,
            bootstrap_nodes: vec![
                "boot1.aevor.io:7777".to_string(),
                "boot2.aevor.io:7777".to_string(),
                "boot3.aevor.io:7777".to_string(),
            ],
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
            db_path: PathBuf::from("/var/lib/aevor/db"),
            create_if_missing: true,
            compression_enabled: true,
            cache_size_mb: 2048, // 2GB cache
            max_open_files: 10000,
            write_buffer_size: 128 * 1024 * 1024, // 128 MB
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
            http_addr: "127.0.0.1".to_string(), // Only listen on localhost by default
            http_port: 8080,
            ws_enabled: true,
            ws_port: 8081,
            jsonrpc_enabled: true,
            jsonrpc_port: 8082,
            cors_enabled: false, // Restricted CORS in production
            cors_allowed_origins: vec![],
            rate_limit_enabled: true,
            rate_limit_requests_per_min: 600, // 10 requests per second
            auth_enabled: true,
            api_keys: vec![],
        },
        vm: VmConfig {
            max_memory_bytes: 128 * 1024 * 1024, // 128 MB
            max_execution_time_ms: 5000,
            gas_limit: 10_000_000,
            gas_price: 1,
            gas_metering_enabled: true,
            debug_enabled: false, // Disabled in production
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
            use_tee: true, // Real TEE in production
            enable_superposition: true,
            max_superpositioned_objects: 1000,
            max_parallel_execution: 32,
        },
    }
}

/// Creates a permissioned production configuration preset
/// This configuration is optimized for enterprise/consortium deployments
pub fn permissioned() -> AevorConfig {
    let mut cfg = config();
    
    // Set permissioned network settings
    cfg.node.name = "Aevor Permissioned Node".to_string();
    
    // More restrictive network settings
    cfg.network.bootstrap_nodes = vec![]; // Typically configured manually
    cfg.network.discovery.method = "static".to_string();
    cfg.network.discovery.enabled = false; // Often disabled in permissioned networks
    
    // More restrictive API settings
    cfg.api.auth_enabled = true;
    cfg.api.rate_limit_enabled = true;
    cfg.api.rate_limit_requests_per_min = 1200; // 20 requests per second
    
    // Permissioned consensus settings
    cfg.consensus.min_validators = 3; // Often fewer validators in permissioned networks
    cfg.consensus.validation_threshold = 51; // Simple majority can be sufficient
    
    // Enhanced privacy settings
    cfg.execution.use_tee = true;
    
    cfg
}

/// Creates a high performance production configuration preset
/// This configuration is optimized for maximum throughput
pub fn high_performance() -> AevorConfig {
    let mut cfg = config();
    
    // Set high performance settings
    cfg.node.name = "Aevor High Performance Node".to_string();
    cfg.node.max_memory_mb = 32768; // 32GB
    
    // Enhanced parallelism
    cfg.execution.max_parallel_execution = 64;
    
    // Larger processing capacity
    cfg.consensus.dual_dag.micro_dag.max_transactions = 5_000_000;
    cfg.consensus.dual_dag.micro_dag.max_dependencies_per_tx = 200;
    cfg.consensus.dual_dag.macro_dag.max_block_size = 8 * 1024 * 1024; // 8 MB
    cfg.consensus.dual_dag.macro_dag.max_transactions_per_block = 50000;
    
    // Enhanced network settings
    cfg.network.max_peers = 100;
    cfg.network.target_outbound_peers = 20;
    cfg.network.enable_rdma_transport = true;
    
    // Enhanced storage settings
    cfg.storage.cache_size_mb = 8192; // 8GB cache
    cfg.storage.max_open_files = 50000;
    cfg.storage.write_buffer_size = 512 * 1024 * 1024; // 512 MB
    
    // Optimized VM settings
    cfg.vm.max_memory_bytes = 512 * 1024 * 1024; // 512 MB
    cfg.execution.max_memory_mb = 512;
    
    cfg
}

/// Creates a validator production configuration preset
/// This configuration is optimized for validator nodes
pub fn validator() -> AevorConfig {
    let mut cfg = config();
    
    // Set validator settings
    cfg.node.name = "Aevor Validator Node".to_string();
    cfg.node.is_validator = true;
    
    // Validator-specific settings
    cfg.consensus.validator.max_parallel_validations = 200;
    cfg.consensus.validator.block_production_rate = 100;
    
    // Enhanced resource allocation
    cfg.node.max_memory_mb = 16384; // 16GB
    cfg.storage.cache_size_mb = 4096; // 4GB cache
    
    // Enhanced network settings for validators
    cfg.network.max_peers = 75;
    cfg.network.target_outbound_peers = 15;
    cfg.network.enable_rdma_transport = true;
    
    // Enhanced security
    cfg.execution.use_tee = true;
    
    cfg
}
