//! Node orchestrator: top-level lifecycle coordination.

use serde::{Deserialize, Serialize};
use aevor_core::network::NodeId;
use aevor_core::tee::TeePlatform;
use crate::{NodeError, NodeResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NodeMode { #[default] Full, Validator, Archive, Light }
impl std::fmt::Display for NodeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Full => write!(f, "full"), Self::Validator => write!(f, "validator"), Self::Archive => write!(f, "archive"), Self::Light => write!(f, "light") }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OrchestratorState { #[default] Initializing, Starting, Running, Stopping, Stopped }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrchestratorConfig { pub mode: NodeMode, pub data_dir: std::path::PathBuf, pub network: String }
impl OrchestratorConfig {
    /// Build an `OrchestratorConfig` from a `NodeConfig`.
    ///
    /// # Errors
    /// Currently always succeeds; `Result` allows future validation of the config fields.
    pub fn from_node_config(cfg: crate::config::NodeConfig, mode: NodeMode) -> NodeResult<Self> {
        Ok(Self { mode, data_dir: cfg.data_dir, network: cfg.network })
    }
}

#[derive(Debug)]
pub struct SubsystemHandle { pub name: String, pub is_running: bool }

#[derive(Debug)]
pub struct NodeHandle {
    peer_id: NodeId,
    network_id: String,
    mode: NodeMode,
    tee_platforms: Vec<TeePlatform>,
}
impl NodeHandle {
    pub fn peer_id(&self) -> &NodeId { &self.peer_id }
    pub fn network_id(&self) -> &str { &self.network_id }
    pub fn mode(&self) -> &NodeMode { &self.mode }
    pub fn active_tee_platforms(&self) -> &[TeePlatform] { &self.tee_platforms }
    /// Shut down this node handle.
    ///
    /// # Errors
    /// Currently always succeeds; `Result` allows future propagation of shutdown errors.
    pub fn shutdown(self) -> NodeResult<()> { Ok(()) }
}

#[derive(Debug)]
pub struct NodeOrchestrator { config: OrchestratorConfig, state: OrchestratorState }
impl NodeOrchestrator {
    /// Create a new orchestrator, validating the configuration.
    ///
    /// # Errors
    /// Returns `NodeError::InvalidConfiguration` if the network identifier is empty.
    pub fn new(config: OrchestratorConfig) -> NodeResult<Self> {
        // Validate config — fail fast on obviously invalid settings.
        if config.network.is_empty() {
            return Err(NodeError::InvalidConfiguration {
                node_type: format!("{}", config.mode),
                reason: "network identifier cannot be empty".into(),
            });
        }
        Ok(Self { config, state: OrchestratorState::Initializing })
    }
    /// Start the orchestrator and return a `NodeHandle`.
    ///
    /// # Errors
    /// Returns an error if the node cannot be started (e.g. port already in use).
    pub fn start(mut self) -> NodeResult<NodeHandle> {
        self.state = OrchestratorState::Running;
        Ok(NodeHandle {
            peer_id: NodeId::from_hash(aevor_core::primitives::Hash256::ZERO),
            network_id: self.config.network.clone(),
            mode: self.config.mode,
            tee_platforms: Vec::new(),
        })
    }
    pub fn state(&self) -> OrchestratorState { self.state }
    pub fn config(&self) -> &OrchestratorConfig { &self.config }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;

    fn config(network: &str) -> OrchestratorConfig {
        OrchestratorConfig {
            mode: NodeMode::Full,
            data_dir: std::path::PathBuf::from("/tmp/aevor-test"),
            network: network.into(),
        }
    }

    #[test]
    fn node_mode_display() {
        assert_eq!(NodeMode::Full.to_string(), "full");
        assert_eq!(NodeMode::Validator.to_string(), "validator");
        assert_eq!(NodeMode::Archive.to_string(), "archive");
        assert_eq!(NodeMode::Light.to_string(), "light");
    }

    #[test]
    fn orchestrator_new_rejects_empty_network() {
        let err = NodeOrchestrator::new(config("")).unwrap_err();
        assert!(err.to_string().contains("network"));
    }

    #[test]
    fn orchestrator_new_accepts_valid_config() {
        let orch = NodeOrchestrator::new(config("testnet")).unwrap();
        assert_eq!(orch.state(), OrchestratorState::Initializing);
    }

    #[test]
    fn orchestrator_start_returns_handle() {
        let orch = NodeOrchestrator::new(config("devnet")).unwrap();
        let handle = orch.start().unwrap();
        assert_eq!(handle.network_id(), "devnet");
        assert_eq!(*handle.mode(), NodeMode::Full);
    }

    #[test]
    fn orchestrator_config_from_node_config() {
        let node_cfg = NodeConfig { data_dir: "/tmp".into(), network: "mainnet".into(), log_level: "info".into() };
        let orch_cfg = OrchestratorConfig::from_node_config(node_cfg, NodeMode::Archive).unwrap();
        assert_eq!(orch_cfg.network, "mainnet");
        assert_eq!(orch_cfg.mode, NodeMode::Archive);
    }

    #[test]
    fn node_handle_shutdown_succeeds() {
        let orch = NodeOrchestrator::new(config("testnet")).unwrap();
        let handle = orch.start().unwrap();
        assert!(handle.shutdown().is_ok());
    }
}
