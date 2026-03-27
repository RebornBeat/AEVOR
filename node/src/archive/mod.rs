//! Archive node (stores full history).
use crate::NodeResult;

#[derive(Debug)]
pub struct ArchiveNode { max_storage_gb: u64, running: bool }
impl ArchiveNode {
    pub fn new(max_storage_gb: u64) -> Self { Self { max_storage_gb, running: false } }
    pub fn max_storage_gb(&self) -> u64 { self.max_storage_gb }
    pub fn is_running(&self) -> bool { self.running }
    /// Start the archive node, returning an error if it is already running.
    ///
    /// # Errors
    /// Returns `NodeError::InitializationFailed` if the node is already running.
    pub fn start(&mut self) -> NodeResult<()> {
        if self.running {
            return Err(crate::NodeError::InitializationFailed {
                subsystem: "archive-node".into(),
                reason: "already running".into(),
            });
        }
        self.running = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_node_starts_not_running() {
        let node = ArchiveNode::new(1000);
        assert!(!node.is_running());
        assert_eq!(node.max_storage_gb(), 1000);
    }

    #[test]
    fn archive_node_start_sets_running() {
        let mut node = ArchiveNode::new(500);
        node.start().unwrap();
        assert!(node.is_running());
    }

    #[test]
    fn archive_node_double_start_fails() {
        let mut node = ArchiveNode::new(500);
        node.start().unwrap();
        assert!(node.start().is_err());
    }
}
