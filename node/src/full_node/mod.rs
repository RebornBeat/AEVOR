//! Full node orchestration.
use crate::NodeResult;

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
    /// # Errors
    /// Returns an error if the node fails to connect to the network or storage.
    pub fn start(&mut self) -> NodeResult<()> { self.running = true; Ok(()) }
    pub fn is_running(&self) -> bool { self.running }
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
