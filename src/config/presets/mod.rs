use std::path::PathBuf;

use super::{
    AevorConfig, ApiConfig, CompactionConfig, ConsensusConfig, DatabaseConfig, DiscoveryConfig,
    DualDagConfig, ExecutionConfig, FinalityConfig, MacroDagConfig, MicroDagConfig, NetworkConfig,
    NodeConfig, PoUConfig, PruningConfig, SecurityAcceleratorConfig, StorageConfig, ValidatorConfig,
    VmConfig,
};

/// Module containing development presets
pub mod development;

/// Module containing production presets
pub mod production;

/// Module containing test presets
pub mod test;

/// Gets the development configuration preset
pub fn development() -> AevorConfig {
    development::config()
}

/// Gets the production configuration preset
pub fn production() -> AevorConfig {
    production::config()
}

/// Gets the test configuration preset
pub fn test() -> AevorConfig {
    test::config()
}

/// Gets the default configuration preset based on the environment
pub fn default_for_environment() -> AevorConfig {
    // Check for environment indicators
    if cfg!(test) {
        test::config()
    } else if cfg!(debug_assertions) {
        development::config()
    } else {
        production::config()
    }
}

/// Loads a named preset configuration
pub fn load_preset(name: &str) -> Option<AevorConfig> {
    match name {
        "development" => Some(development::config()),
        "production" => Some(production::config()),
        "test" => Some(test::config()),
        "permissioned" => Some(production::permissioned()),
        "high_performance" => Some(production::high_performance()),
        "minimal" => Some(development::minimal()),
        "local_cluster" => Some(development::local_cluster()),
        _ => None,
    }
}

/// Lists available preset names
pub fn available_presets() -> Vec<&'static str> {
    vec![
        "development",
        "production",
        "test",
        "permissioned",
        "high_performance",
        "minimal",
        "local_cluster",
    ]
}
