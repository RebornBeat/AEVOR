//! Archive node (stores full history).
use crate::NodeResult;

pub struct ArchiveNode { max_storage_gb: u64, running: bool }
impl ArchiveNode {
    pub fn new(max_storage_gb: u64) -> Self { Self { max_storage_gb, running: false } }
    pub fn max_storage_gb(&self) -> u64 { self.max_storage_gb }
}
