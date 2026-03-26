//! Multi-TEE execution orchestration.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_core::tee::TeePlatform;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeCoordinationContext {
    pub session_id: Hash256,
    pub platforms: Vec<TeePlatform>,
    pub consensus_threshold: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistributedExecution {
    pub context: TeeCoordinationContext,
    pub results: Vec<Hash256>,
}

pub struct TeeConsistencyVerifier;
impl TeeConsistencyVerifier {
    pub fn all_agree(results: &[Hash256]) -> bool {
        results.windows(2).all(|w| w[0] == w[1])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiTeeResult { pub agreed_hash: Option<Hash256>, pub platform_count: usize }

pub struct TeeInstanceSelector { preferred: Option<TeePlatform> }
impl TeeInstanceSelector {
    pub fn new(preferred: Option<TeePlatform>) -> Self { Self { preferred } }
    pub fn select(&self, available: &[TeePlatform]) -> Option<TeePlatform> {
        self.preferred.and_then(|p| available.iter().find(|&&a| a == p).copied())
            .or_else(|| available.first().copied())
    }
}

pub struct MultiTeeOrchestrator { coordinators: Vec<TeeCoordinationContext> }
impl MultiTeeOrchestrator {
    pub fn new() -> Self { Self { coordinators: Vec::new() } }
    pub fn add(&mut self, ctx: TeeCoordinationContext) { self.coordinators.push(ctx); }
    pub fn count(&self) -> usize { self.coordinators.len() }
}
impl Default for MultiTeeOrchestrator { fn default() -> Self { Self::new() } }
