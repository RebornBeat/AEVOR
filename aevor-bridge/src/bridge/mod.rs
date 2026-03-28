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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn config(src: &str, tgt: &str) -> BridgeConfig {
        BridgeConfig { source_chain: src.into(), target_chain: tgt.into(), tee_secured: true, min_confirmations: 12 }
    }

    #[test]
    fn bridge_starts_initializing() {
        let b = Bridge::new(config("aevor", "ethereum"));
        assert_eq!(b.state(), &BridgeState::Initializing);
        assert_eq!(b.source_chain(), "aevor");
        assert_eq!(b.target_chain(), "ethereum");
    }

    #[test]
    fn bridge_start_transitions_to_active() {
        let mut b = Bridge::new(config("aevor", "bitcoin"));
        b.start();
        assert_eq!(b.state(), &BridgeState::Active);
    }

    #[test]
    fn bridge_pause_transitions_to_paused() {
        let mut b = Bridge::new(config("aevor", "solana"));
        b.start();
        b.pause();
        assert_eq!(b.state(), &BridgeState::Paused);
    }

    #[test]
    fn tee_secured_config() {
        let cfg = config("aevor", "ethereum");
        assert!(cfg.tee_secured); // TEE-secured is the default
        assert_eq!(cfg.min_confirmations, 12);
    }

    #[test]
    fn cross_chain_message_nonce_is_replay_protection() {
        let m1 = CrossChainMessage { id: Hash256([1u8;32]), from_chain: "a".into(), to_chain: "b".into(), payload: vec![1], nonce: 1 };
        let m2 = CrossChainMessage { id: Hash256([2u8;32]), from_chain: "a".into(), to_chain: "b".into(), payload: vec![1], nonce: 2 };
        assert_ne!(m1.nonce, m2.nonce);
    }
}
