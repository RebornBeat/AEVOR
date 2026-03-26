//! Full node orchestration.
use crate::NodeResult;

pub struct StorageHandle { pub connected: bool }
pub struct ApiHandle { pub running: bool }
pub struct FullNodeNetworkHandle { pub peer_count: usize }

pub struct FullNodeOrchestrator;
pub struct FullNode { running: bool }
impl FullNode {
    pub fn new() -> Self { Self { running: false } }
    pub async fn start(&mut self) -> NodeResult<()> { self.running = true; Ok(()) }
    pub fn is_running(&self) -> bool { self.running }
}
impl Default for FullNode { fn default() -> Self { Self::new() } }
