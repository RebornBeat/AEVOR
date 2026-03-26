//! State pruning: removing old data while preserving finality guarantees.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::BlockHeight;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningConfig {
    pub enabled: bool,
    pub keep_blocks: u64,
    pub keep_state_versions: u64,
    pub checkpoint_interval: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_blocks: 10_000,
            keep_state_versions: 1_000,
            checkpoint_interval: 1_000,
        }
    }
}

pub struct Pruner {
    config: PruningConfig,
}

impl Pruner {
    pub fn new(config: PruningConfig) -> Self { Self { config } }

    pub fn should_prune(&self, current_height: BlockHeight, target_height: BlockHeight) -> bool {
        self.config.enabled
            && current_height.as_u64() > target_height.as_u64() + self.config.keep_blocks
    }
}
