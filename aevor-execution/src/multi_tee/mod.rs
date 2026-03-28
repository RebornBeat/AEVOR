//! Multi-TEE execution orchestration.
//!
//! Cross-platform TEE consistency is a core AEVOR guarantee: identical inputs
//! must produce identical outputs across all five supported platforms (Intel SGX,
//! AMD SEV, ARM TrustZone, RISC-V Keystone, AWS Nitro). This module coordinates
//! multi-platform execution and verifies behavioral consistency.

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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::tee::TeePlatform;

    const ALL_PLATFORMS: [TeePlatform; 5] = [
        TeePlatform::IntelSgx,
        TeePlatform::AmdSev,
        TeePlatform::ArmTrustZone,
        TeePlatform::RiscvKeystone,
        TeePlatform::AwsNitro,
    ];

    fn hash(n: u8) -> Hash256 { Hash256([n; 32]) }

    // ── Cross-platform consistency (whitepaper core guarantee) ──────────

    #[test]
    fn all_five_platforms_are_representable() {
        // Whitepaper: identical inputs produce identical outputs across all 5 platforms
        let ctx = TeeCoordinationContext {
            session_id: hash(1),
            platforms: ALL_PLATFORMS.to_vec(),
            consensus_threshold: 3,
        };
        assert_eq!(ctx.platforms.len(), 5);
        assert!(ctx.platforms.contains(&TeePlatform::IntelSgx));
        assert!(ctx.platforms.contains(&TeePlatform::AmdSev));
        assert!(ctx.platforms.contains(&TeePlatform::ArmTrustZone));
        assert!(ctx.platforms.contains(&TeePlatform::RiscvKeystone));
        assert!(ctx.platforms.contains(&TeePlatform::AwsNitro));
    }

    // ── TeeConsistencyVerifier ──────────────────────────────────────────

    #[test]
    fn all_agree_with_identical_results() {
        let results = vec![hash(42), hash(42), hash(42), hash(42), hash(42)];
        assert!(TeeConsistencyVerifier::all_agree(&results));
    }

    #[test]
    fn all_agree_fails_with_divergent_result() {
        // One platform produced a different hash — corruption detected
        let results = vec![hash(1), hash(1), hash(99), hash(1)];
        assert!(!TeeConsistencyVerifier::all_agree(&results));
    }

    #[test]
    fn all_agree_empty_and_single_are_consistent() {
        assert!(TeeConsistencyVerifier::all_agree(&[]));
        assert!(TeeConsistencyVerifier::all_agree(&[hash(7)]));
    }

    // ── TeeInstanceSelector ─────────────────────────────────────────────

    #[test]
    fn selector_picks_preferred_when_available() {
        let sel = TeeInstanceSelector::new(Some(TeePlatform::AmdSev));
        let available = vec![TeePlatform::IntelSgx, TeePlatform::AmdSev, TeePlatform::AwsNitro];
        assert_eq!(sel.select(&available), Some(TeePlatform::AmdSev));
    }

    #[test]
    fn selector_falls_back_to_first_when_preferred_unavailable() {
        let sel = TeeInstanceSelector::new(Some(TeePlatform::RiscvKeystone));
        let available = vec![TeePlatform::IntelSgx, TeePlatform::AmdSev];
        assert_eq!(sel.select(&available), Some(TeePlatform::IntelSgx));
    }

    #[test]
    fn selector_no_preference_returns_first() {
        let sel = TeeInstanceSelector::new(None);
        let available = vec![TeePlatform::ArmTrustZone, TeePlatform::AwsNitro];
        assert_eq!(sel.select(&available), Some(TeePlatform::ArmTrustZone));
    }

    #[test]
    fn selector_empty_available_returns_none() {
        let sel = TeeInstanceSelector::new(Some(TeePlatform::IntelSgx));
        assert_eq!(sel.select(&[]), None);
    }

    // ── MultiTeeOrchestrator ────────────────────────────────────────────

    #[test]
    fn orchestrator_add_and_count() {
        let mut orch = MultiTeeOrchestrator::new();
        orch.add(TeeCoordinationContext {
            session_id: hash(1),
            platforms: vec![TeePlatform::IntelSgx],
            consensus_threshold: 1,
        });
        orch.add(TeeCoordinationContext {
            session_id: hash(2),
            platforms: vec![TeePlatform::AmdSev],
            consensus_threshold: 1,
        });
        assert_eq!(orch.count(), 2);
    }
}
