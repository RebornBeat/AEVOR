//! Node configuration.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub data_dir: std::path::PathBuf,
    pub network: String,
    pub log_level: String,
}
impl Default for NodeConfig {
    fn default() -> Self {
        let mut data_dir = dirs::home_dir().unwrap_or_default();
        data_dir.push(".aevor");
        data_dir.push("data");
        Self { data_dir, network: "mainnet".into(), log_level: "info".into() }
    }
}
impl NodeConfig {
    /// Load a `NodeConfig` from a TOML file at `path`.
    ///
    /// # Errors
    /// Returns `NodeError::InvalidConfiguration` if the file cannot be read or the
    /// TOML is malformed.
    pub fn from_file(path: &std::path::Path) -> crate::NodeResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| crate::NodeError::InvalidConfiguration {
            node_type: "node".into(), reason: e.to_string(),
        })?;
        toml::from_str(&content).map_err(|e| crate::NodeError::InvalidConfiguration {
            node_type: "node".into(), reason: e.to_string(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ValidatorConfig { pub key_file: Option<std::path::PathBuf>, pub tee_platform: String }
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct FullNodeConfig { pub enable_api: bool }
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ArchiveConfig { pub max_storage_gb: u64 }
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LightNodeConfig { pub checkpoint: Option<String> }
