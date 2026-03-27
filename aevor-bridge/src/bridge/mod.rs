//! Core bridge orchestration.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeConfig {
    pub source_chain: String, pub target_chain: String,
    pub tee_secured: bool, pub min_confirmations: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossChainMessage {
    pub id: Hash256, pub from_chain: String, pub to_chain: String,
    pub payload: Vec<u8>, pub nonce: u64,
}
#[derive(Clone, Debug)]
pub struct BridgeHandle { pub id: Hash256 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainConnection { pub chain_id: String, pub endpoint: String, pub connected: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BridgeState { Initializing, Active, Paused, Stopped }

pub struct Bridge { config: BridgeConfig, state: BridgeState }
impl Bridge {
    pub fn new(config: BridgeConfig) -> Self { Self { config, state: BridgeState::Initializing } }
    pub fn config(&self) -> &BridgeConfig { &self.config }
    pub fn source_chain(&self) -> &str { &self.config.source_chain }
    pub fn target_chain(&self) -> &str { &self.config.target_chain }
    pub fn state(&self) -> &BridgeState { &self.state }
    pub fn start(&mut self) { self.state = BridgeState::Active; }
    pub fn pause(&mut self) { self.state = BridgeState::Paused; }
}
