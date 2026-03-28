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
    pub fn total_count(&self) -> usize { self.relayers.len() }
}
impl Default for RelayerSet { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn relayer(n: u8, active: bool) -> RelayerEntry {
        RelayerEntry { id: Hash256([n; 32]), endpoint: format!("http://relay-{n}.example.com"), active }
    }

    #[test]
    fn relayer_set_tracks_active_count() {
        let mut rs = RelayerSet::new();
        rs.add(relayer(1, true));
        rs.add(relayer(2, false));
        rs.add(relayer(3, true));
        assert_eq!(rs.active_count(), 2);
        assert_eq!(rs.total_count(), 3);
    }

    #[test]
    fn relayer_consensus_threshold() {
        let cons = RelayerConsensus::new(3);
        assert!(!cons.has_consensus(2));
        assert!(cons.has_consensus(3));
        assert!(cons.has_consensus(10));
    }

    #[test]
    fn relay_message_cross_chain_routing() {
        let msg = RelayMessage { id: Hash256::ZERO, payload: vec![1,2,3], from_chain: "aevor".into(), to_chain: "ethereum".into() };
        assert_eq!(msg.from_chain, "aevor");
        assert_eq!(msg.to_chain, "ethereum");
    }

    #[test]
    fn relay_confirmation_tracks_confirmers() {
        let conf = RelayConfirmation { message_id: Hash256::ZERO, confirmed_by: vec![Hash256([1u8;32]), Hash256([2u8;32])] };
        assert_eq!(conf.confirmed_by.len(), 2);
    }
}
