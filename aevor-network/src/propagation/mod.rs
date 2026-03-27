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
