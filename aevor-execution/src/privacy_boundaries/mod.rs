//! Privacy boundary enforcement during execution.
//!
//! Mixed privacy execution is a core AEVOR feature: a single transaction can
//! span objects at different privacy levels. The boundary enforcement layer
//! mediates information flow across those boundaries using TEE secure channels,
//! ZK proofs, or selective disclosure — whichever the application policy requires.
//!
//! **Infrastructure vs Policy:** `BoundaryEnforcement` provides capability primitives.
//! *Which* objects cross *which* boundaries is application policy, not infrastructure.

use serde::{Deserialize, Serialize};
use aevor_core::privacy::{PrivacyBoundary, PrivacyLevel};
use aevor_core::primitives::Hash256;

pub struct PrivacyBoundaryManager { boundaries: Vec<PrivacyBoundary> }
impl PrivacyBoundaryManager {
    pub fn new() -> Self { Self { boundaries: Vec::new() } }
    pub fn add(&mut self, b: PrivacyBoundary) { self.boundaries.push(b); }
    pub fn boundary_count(&self) -> usize { self.boundaries.len() }
    /// Returns `true` if any registered boundary allows crossing.
    pub fn has_crossable_boundary(&self) -> bool {
        self.boundaries.iter().any(PrivacyBoundary::allows_crossing)
    }
}
impl Default for PrivacyBoundaryManager { fn default() -> Self { Self::new() } }

/// Enforces information flow across privacy boundaries.
///
/// In `strict` mode: information can only flow from less private to more private
/// contexts (e.g. Public → Private). Reverse flow requires explicit disclosure.
/// In non-strict mode: crossing is allowed in both directions, enabling
/// selective disclosure patterns that the application coordinates.
pub struct BoundaryEnforcement { strict: bool }
impl BoundaryEnforcement {
    pub fn new(strict: bool) -> Self { Self { strict } }
    /// Returns `true` if crossing from `from` to `to` is allowed.
    pub fn allows_crossing(&self, from: PrivacyLevel, to: PrivacyLevel) -> bool {
        !self.strict || from <= to
    }
}

pub struct CrossPrivacyMediator;
pub struct PrivacyAwareExecution { pub effective_level: PrivacyLevel }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BoundaryViolationProof {
    pub violating_operation: Hash256,
    pub from_level: PrivacyLevel,
    pub to_level: PrivacyLevel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::privacy::{CrossPrivacyDisclosureMode, PrivacyBoundary, PrivacyLevel};
    use aevor_core::primitives::Hash256;

    fn boundary(inner: PrivacyLevel, outer: PrivacyLevel, modes: Vec<CrossPrivacyDisclosureMode>) -> PrivacyBoundary {
        PrivacyBoundary { inner_level: inner, outer_level: outer, permitted_modes: modes }
    }

    // ── PrivacyBoundaryManager ────────────────────────────────────────────

    #[test]
    fn manager_starts_empty() {
        let mgr = PrivacyBoundaryManager::new();
        assert_eq!(mgr.boundary_count(), 0);
        assert!(!mgr.has_crossable_boundary());
    }

    #[test]
    fn manager_add_crossable_boundary() {
        let mut mgr = PrivacyBoundaryManager::new();
        mgr.add(boundary(
            PrivacyLevel::Private, PrivacyLevel::Public,
            vec![CrossPrivacyDisclosureMode::CommitmentOnly],
        ));
        assert_eq!(mgr.boundary_count(), 1);
        assert!(mgr.has_crossable_boundary());
    }

    #[test]
    fn manager_non_crossable_boundary_not_crossable() {
        let mut mgr = PrivacyBoundaryManager::new();
        mgr.add(boundary(PrivacyLevel::Confidential, PrivacyLevel::Private, vec![]));
        assert!(!mgr.has_crossable_boundary());
    }

    // ── BoundaryEnforcement ───────────────────────────────────────────────
    // Whitepaper: "Mixed privacy coordination enables applications to implement
    // business logic that spans both confidential and transparent operations."

    #[test]
    fn strict_enforcement_allows_public_to_private() {
        // Public → Private: information flowing into a more private context is safe
        let e = BoundaryEnforcement::new(true);
        assert!(e.allows_crossing(PrivacyLevel::Public, PrivacyLevel::Private));
    }

    #[test]
    fn strict_enforcement_blocks_private_to_public() {
        // Private → Public: would leak confidential data — blocked in strict mode
        let e = BoundaryEnforcement::new(true);
        assert!(!e.allows_crossing(PrivacyLevel::Private, PrivacyLevel::Public));
    }

    #[test]
    fn strict_enforcement_allows_same_level() {
        let e = BoundaryEnforcement::new(true);
        assert!(e.allows_crossing(PrivacyLevel::Private, PrivacyLevel::Private));
    }

    #[test]
    fn non_strict_allows_crossing_in_both_directions() {
        // Non-strict: application coordinates disclosure policy
        let e = BoundaryEnforcement::new(false);
        assert!(e.allows_crossing(PrivacyLevel::Confidential, PrivacyLevel::Public));
        assert!(e.allows_crossing(PrivacyLevel::Public, PrivacyLevel::Confidential));
    }

    // ── BoundaryViolationProof ────────────────────────────────────────────

    #[test]
    fn violation_proof_stores_levels() {
        let proof = BoundaryViolationProof {
            violating_operation: Hash256([0xFF; 32]),
            from_level: PrivacyLevel::Confidential,
            to_level: PrivacyLevel::Public,
        };
        assert_eq!(proof.from_level, PrivacyLevel::Confidential);
        assert_eq!(proof.to_level, PrivacyLevel::Public);
    }

    // ── PrivacyAwareExecution ─────────────────────────────────────────────
    // Whitepaper: effective level = maximum privacy of all participating objects

    #[test]
    fn privacy_aware_execution_stores_effective_level() {
        let exec = PrivacyAwareExecution { effective_level: PrivacyLevel::Private };
        assert_eq!(exec.effective_level, PrivacyLevel::Private);
        assert!(exec.effective_level.requires_tee());
    }
}
