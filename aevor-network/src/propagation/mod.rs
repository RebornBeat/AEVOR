//! Block and transaction propagation.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{BlockHash, TransactionHash};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PropagationPolicy { pub fanout: usize, pub ttl_hops: u8 }
impl Default for PropagationPolicy { fn default() -> Self { Self { fanout: 8, ttl_hops: 10 } } }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BroadcastResult { pub reached: usize, pub failed: usize }

pub struct BlockPropagator { policy: PropagationPolicy }
impl BlockPropagator {
    pub fn new(policy: PropagationPolicy) -> Self { Self { policy } }
    pub fn fanout(&self) -> usize { self.policy.fanout }
    /// Build a propagation announcement for `block_hash`.
    pub fn announce(&self, block_hash: BlockHash) -> PropagationAnnouncement {
        PropagationAnnouncement::Block(block_hash)
    }
}

pub struct TransactionPropagator { policy: PropagationPolicy }
impl TransactionPropagator {
    pub fn new(policy: PropagationPolicy) -> Self { Self { policy } }
    pub fn fanout(&self) -> usize { self.policy.fanout }
    /// Build a propagation announcement for `tx_hash`.
    pub fn announce(&self, tx_hash: TransactionHash) -> PropagationAnnouncement {
        PropagationAnnouncement::Transaction(tx_hash)
    }
}

/// A network propagation announcement for a block or transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PropagationAnnouncement {
    Block(BlockHash),
    Transaction(TransactionHash),
}

pub struct DagAwarePropagation;

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn bh(n: u8) -> BlockHash { Hash256([n; 32]) }
    fn th(n: u8) -> TransactionHash { Hash256([n; 32]) }

    #[test]
    fn propagation_policy_default_fanout_and_ttl() {
        let p = PropagationPolicy::default();
        assert_eq!(p.fanout, 8);
        assert_eq!(p.ttl_hops, 10);
    }

    #[test]
    fn block_propagator_announces_block() {
        let prop = BlockPropagator::new(PropagationPolicy::default());
        assert_eq!(prop.fanout(), 8);
        let ann = prop.announce(bh(1));
        assert!(matches!(ann, PropagationAnnouncement::Block(_)));
    }

    #[test]
    fn transaction_propagator_announces_tx() {
        let prop = TransactionPropagator::new(PropagationPolicy::default());
        let ann = prop.announce(th(2));
        assert!(matches!(ann, PropagationAnnouncement::Transaction(_)));
    }

    #[test]
    fn broadcast_result_tracks_reached_and_failed() {
        let r = BroadcastResult { reached: 7, failed: 1 };
        assert_eq!(r.reached + r.failed, 8);
    }
}
