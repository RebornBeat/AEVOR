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
    pub fn from_node_config(cfg: crate::config::NodeConfig, mode: NodeMode) -> NodeResult<Self> {
        Ok(Self { mode, data_dir: cfg.data_dir, network: cfg.network })
    }
}

pub struct SubsystemHandle { pub name: String, pub is_running: bool }

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
    pub async fn shutdown(self) -> NodeResult<()> { Ok(()) }
}

pub struct NodeOrchestrator { config: OrchestratorConfig, state: OrchestratorState }
impl NodeOrchestrator {
    pub async fn new(config: OrchestratorConfig) -> NodeResult<Self> {
        Ok(Self { config, state: OrchestratorState::Initializing })
    }
    pub async fn start(mut self) -> NodeResult<NodeHandle> {
        self.state = OrchestratorState::Running;
        Ok(NodeHandle {
            peer_id: NodeId::from_hash(aevor_core::primitives::Hash256::ZERO),
            network_id: self.config.network.clone(),
            mode: self.config.mode,
            tee_platforms: Vec::new(),
        })
    }
    pub fn state(&self) -> OrchestratorState { self.state }
}
