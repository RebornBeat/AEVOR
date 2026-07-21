//! Full node orchestration.
use crate::engine::{BlockOutcome, NodeEngine};
use crate::{NodeError, NodeResult};

#[derive(Debug)]
pub struct StorageHandle { pub connected: bool }
#[derive(Debug)]
pub struct ApiHandle { pub running: bool }
#[derive(Debug)]
pub struct FullNodeNetworkHandle { pub peer_count: usize }

pub struct FullNodeOrchestrator;
#[derive(Debug)]
pub struct FullNode { running: bool }
impl FullNode {
    pub fn new() -> Self { Self { running: false } }
    /// Start the full node.
    ///
    /// Sizes the compute pool to the host's cores so intra-lane parallel
    /// execution uses all available hardware (see [`crate::compute`]).
    ///
    /// # Errors
    /// Returns an error if the node fails to connect to the network or storage.
    pub fn start(&mut self) -> NodeResult<()> {
        // Scale parallel execution to this validator's hardware. Not an error if
        // the global pool was already configured elsewhere.
        let _ = crate::compute::ComputeProfile::detect().configure();
        self.running = true;
        Ok(())
    }
    pub fn is_running(&self) -> bool { self.running }

    /// Produce a block from the engine's mempool.
    ///
    /// A full node maintains full state and executes transactions, but does not
    /// itself finalize — that is a validator role. All modes drive the same
    /// [`NodeEngine`]; they differ only in policy.
    ///
    /// # Errors
    /// Returns `NodeError::InitializationFailed` if the node has not been
    /// started, or propagates an engine error.
    pub fn produce_block(&self, engine: &mut NodeEngine) -> NodeResult<BlockOutcome> {
        if !self.running {
            return Err(NodeError::InitializationFailed {
                subsystem: "full-node".into(),
                reason: "cannot produce a block before start()".into(),
            });
        }
        engine.produce_block()
    }
}
impl Default for FullNode { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_node_starts_not_running() {
        assert!(!FullNode::new().is_running());
    }

    #[test]
    fn full_node_start_sets_running() {
        let mut node = FullNode::new();
        node.start().unwrap();
        assert!(node.is_running());
    }
}
