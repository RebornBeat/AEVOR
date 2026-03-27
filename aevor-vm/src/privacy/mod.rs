//! Mixed-privacy execution within the VM.
//!
//! Objects with different privacy levels can coexist in a single transaction.
//! `MixedPrivacyExecutor` determines the effective privacy level (highest of all
//! accessed objects) and enforces that boundary crossing is permitted.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::ObjectId;
use aevor_core::privacy::{MixedPrivacyExecution, PrivacyLevel};

/// Determines and enforces the effective privacy level for a multi-object operation.
pub struct MixedPrivacyExecutor;

impl MixedPrivacyExecutor {
    /// Compute the effective privacy level as the maximum of all accessed objects.
    ///
    /// If any accessed object is `Private`, the whole execution runs as `Private`.
    pub fn determine_effective_level(objects: &[(ObjectId, PrivacyLevel)]) -> PrivacyLevel {
        objects.iter().map(|(_, l)| *l).max().unwrap_or(PrivacyLevel::Public)
    }

    /// Build a `MixedPrivacyExecution` plan from the object access set.
    ///
    /// The plan captures each object's privacy requirement and the computed
    /// effective level, and is passed to the TEE allocator for enclave selection.
    pub fn build_plan(objects: &[(ObjectId, PrivacyLevel)]) -> MixedPrivacyExecution {
        let map: std::collections::HashMap<String, PrivacyLevel> = objects
            .iter()
            .map(|(id, level)| (hex::encode(id.as_hash().0), *level))
            .collect();
        MixedPrivacyExecution::from_objects(map)
    }

    /// Returns `true` if the given object set requires TEE execution (any object is Private).
    pub fn requires_tee(objects: &[(ObjectId, PrivacyLevel)]) -> bool {
        objects.iter().any(|(_, l)| *l == PrivacyLevel::Private)
    }
}

/// Enforces privacy boundary rules during execution.
pub struct PrivacyBoundaryEnforcer {
    strict: bool,
}

impl PrivacyBoundaryEnforcer {
    /// Create a boundary enforcer.
    ///
    /// In `strict` mode, lowering the privacy level (Private → Public) is rejected.
    pub fn new(strict: bool) -> Self { Self { strict } }

    /// Check if crossing from `from` to `to` is allowed.
    ///
    /// # Errors
    /// Returns `VmError::PrivacyViolation` if the enforcer is in strict mode and
    /// `from` is more private than `to` (lowering the privacy level is rejected).
    pub fn check_crossing(&self, from: PrivacyLevel, to: PrivacyLevel) -> crate::VmResult<()> {
        if self.strict && from > to {
            return Err(crate::VmError::PrivacyViolation {
                description: "cannot lower privacy level in strict mode".into(),
            });
        }
        Ok(())
    }

    /// Returns `true` if `level` requires a TEE-isolated execution context.
    pub fn requires_isolation(&self, level: PrivacyLevel) -> bool {
        level == PrivacyLevel::Private
    }
}

/// A contract that accesses objects of mixed privacy levels.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossPrivacyContract {
    /// Address of the contract.
    pub contract: aevor_core::primitives::Address,
    /// Whether this contract crosses a privacy boundary.
    pub crosses_boundary: bool,
}

/// A VM-layer selective disclosure controller.
///
/// Allows contracts to selectively reveal private state to authorized viewers
/// without changing the object's stored privacy level.
pub struct SelectiveDisclosureVm;

impl SelectiveDisclosureVm {
    /// Check if `viewer` is authorized to see data at `level`.
    pub fn is_authorized(
        _viewer: &aevor_core::primitives::Address,
        level: PrivacyLevel,
    ) -> bool {
        // Full implementation: verify viewer against the object's disclosure policy.
        // Public objects: always visible. Private: check disclosure grant.
        level == PrivacyLevel::Public
    }
}

/// TEE-isolated private state store for a single contract execution.
pub struct PrivateStateManager {
    entries: std::collections::HashMap<Vec<u8>, Vec<u8>>,
}

impl PrivateStateManager {
    /// Create a new empty private state store.
    pub fn new() -> Self { Self { entries: std::collections::HashMap::new() } }
    /// Store a private value.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) { self.entries.insert(key, value); }
    /// Retrieve a private value.
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> { self.entries.get(key) }
    /// Number of private entries.
    pub fn entry_count(&self) -> usize { self.entries.len() }
}

impl Default for PrivateStateManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::ObjectId;
    use aevor_core::primitives::Hash256;

    fn obj(n: u8) -> (ObjectId, PrivacyLevel) {
        (ObjectId(Hash256([n; 32])), if n % 2 == 0 { PrivacyLevel::Public } else { PrivacyLevel::Private })
    }

    #[test]
    fn effective_level_is_max() {
        let objects = vec![obj(0), obj(1), obj(2)]; // Public, Private, Public
        assert_eq!(MixedPrivacyExecutor::determine_effective_level(&objects), PrivacyLevel::Private);
    }

    #[test]
    fn all_public_stays_public() {
        let objects = vec![obj(0), obj(2)];
        assert_eq!(MixedPrivacyExecutor::determine_effective_level(&objects), PrivacyLevel::Public);
    }

    #[test]
    fn requires_tee_when_private() {
        assert!(MixedPrivacyExecutor::requires_tee(&[obj(1)]));
        assert!(!MixedPrivacyExecutor::requires_tee(&[obj(0)]));
    }

    #[test]
    fn build_plan_captures_effective_level() {
        let objects = vec![obj(0), obj(1)];
        let plan = MixedPrivacyExecutor::build_plan(&objects);
        assert_eq!(plan.effective_level, PrivacyLevel::Private);
    }

    #[test]
    fn strict_enforcer_rejects_downgrade() {
        let enforcer = PrivacyBoundaryEnforcer::new(true);
        assert!(enforcer.check_crossing(PrivacyLevel::Private, PrivacyLevel::Public).is_err());
        assert!(enforcer.check_crossing(PrivacyLevel::Public, PrivacyLevel::Private).is_ok());
    }

    #[test]
    fn lenient_enforcer_allows_downgrade() {
        let enforcer = PrivacyBoundaryEnforcer::new(false);
        assert!(enforcer.check_crossing(PrivacyLevel::Private, PrivacyLevel::Public).is_ok());
    }
}
