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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::BlockHeight;

    #[test]
    fn pruning_config_default_enabled() {
        let cfg = PruningConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.keep_blocks > 0);
        assert!(cfg.keep_state_versions > 0);
    }

    #[test]
    fn pruner_should_prune_when_far_ahead() {
        let pruner = Pruner::new(PruningConfig { keep_blocks: 100, ..PruningConfig::default() });
        // current=500, target=0 → 500 > 0 + 100 → should prune
        assert!(pruner.should_prune(BlockHeight(500), BlockHeight(0)));
    }

    #[test]
    fn pruner_should_not_prune_within_keep_window() {
        let pruner = Pruner::new(PruningConfig { keep_blocks: 1000, ..PruningConfig::default() });
        // current=500, target=0 → 500 < 0 + 1000 → no prune
        assert!(!pruner.should_prune(BlockHeight(500), BlockHeight(0)));
    }

    #[test]
    fn pruner_disabled_never_prunes() {
        let pruner = Pruner::new(PruningConfig { enabled: false, keep_blocks: 1, ..PruningConfig::default() });
        assert!(!pruner.should_prune(BlockHeight(1_000_000), BlockHeight(0)));
    }
}
