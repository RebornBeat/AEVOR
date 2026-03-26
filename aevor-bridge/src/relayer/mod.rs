//! TEE-secured bridge relayer set.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayerEntry { pub id: Hash256, pub endpoint: String, pub active: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayMessage { pub id: Hash256, pub payload: Vec<u8>, pub from_chain: String, pub to_chain: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConfirmation { pub message_id: Hash256, pub confirmed_by: Vec<Hash256> }
pub struct ValidatorRelayer { pub validator: aevor_core::primitives::ValidatorId }
pub struct RelayerConsensus { pub threshold: usize }
impl RelayerConsensus {
    pub fn new(threshold: usize) -> Self { Self { threshold } }
    pub fn has_consensus(&self, confirmations: usize) -> bool { confirmations >= self.threshold }
}

pub struct RelayerSet { relayers: Vec<RelayerEntry> }
impl RelayerSet {
    pub fn new() -> Self { Self { relayers: Vec::new() } }
    pub fn add(&mut self, r: RelayerEntry) { self.relayers.push(r); }
    pub fn active_count(&self) -> usize { self.relayers.iter().filter(|r| r.active).count() }
}
impl Default for RelayerSet { fn default() -> Self { Self::new() } }
