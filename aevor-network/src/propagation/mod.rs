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
}

pub struct TransactionPropagator { policy: PropagationPolicy }
impl TransactionPropagator {
    pub fn new(policy: PropagationPolicy) -> Self { Self { policy } }
}

pub struct DagAwarePropagation;
