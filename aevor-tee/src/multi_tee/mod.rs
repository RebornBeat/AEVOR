//! Multi-TEE coordination: distributed secure execution across multiple instances.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_core::tee::TeePlatform;
use crate::TeeResult;

/// A single TEE instance participating in a multi-TEE coordination session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeInstance {
    /// Unique identifier for this TEE instance.
    pub id: Hash256,
    /// Hardware platform this instance runs on.
    pub platform: TeePlatform,
    /// Validator that operates this TEE instance.
    pub validator_id: aevor_core::primitives::ValidatorId,
    /// Whether this instance is currently active and accepting requests.
    pub is_active: bool,
    /// Attestation report proving this instance's authenticity (if verified).
    pub attestation: Option<aevor_core::tee::AttestationReport>,
}

impl TeeInstance {
    /// Returns `true` if this instance has a verified attestation.
    pub fn is_attested(&self) -> bool { self.attestation.is_some() }

    /// Returns `true` if this instance is both active and attested.
    pub fn is_ready(&self) -> bool { self.is_active && self.is_attested() }
}

/// A distributed TEE execution session across multiple instances.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistributedTeeExecution {
    /// Unique session identifier.
    pub session_id: Hash256,
    /// TEE instances participating in this session.
    pub participating_instances: Vec<TeeInstance>,
    /// Minimum number of instances that must agree on the result.
    pub consensus_threshold: usize,
    /// Hash of the agreed-upon computation result (set after consensus).
    pub result_hash: Option<Hash256>,
}

impl DistributedTeeExecution {
    /// Create a new distributed execution session.
    pub fn new(instances: Vec<TeeInstance>, threshold: usize) -> Self {
        Self {
            session_id: Hash256([0u8; 32]),
            participating_instances: instances,
            consensus_threshold: threshold,
            result_hash: None,
        }
    }

    /// Number of TEE instances in this session.
    pub fn instance_count(&self) -> usize { self.participating_instances.len() }

    /// Returns `true` if enough instances are present to meet the threshold.
    pub fn meets_threshold(&self) -> bool {
        self.instance_count() >= self.consensus_threshold
    }

    /// Returns `true` if a consensus result has been recorded.
    pub fn has_result(&self) -> bool { self.result_hash.is_some() }
}

/// Verifies that multiple TEE instances agree on a computation result.
pub struct TeeConsistencyVerifier;

impl TeeConsistencyVerifier {
    /// Verify that a majority of instances agree on `expected_hash`.
    ///
    /// Counts attested instances whose code measurement matches `expected_hash`.
    /// Returns `true` if more than half agree.
    pub fn verify_consistency(
        instances: &[TeeInstance],
        expected_hash: &Hash256,
    ) -> TeeResult<bool> {
        let attested_count = instances.iter()
            .filter(|i| {
                i.attestation.as_ref()
                    .map(|a| &a.code_measurement == expected_hash)
                    .unwrap_or(false)
            })
            .count();
        Ok(attested_count > instances.len() / 2)
    }
}

/// Fault-tolerant TEE execution with automatic failover.
///
/// Maintains a pool of TEE instances and returns healthy status as long as
/// at least `min_active` instances are active.
pub struct FaultTolerantTee {
    instances: Vec<TeeInstance>,
    min_active: usize,
}

impl FaultTolerantTee {
    /// Create a fault-tolerant pool requiring at least `min_active` live instances.
    pub fn new(instances: Vec<TeeInstance>, min_active: usize) -> Self {
        Self { instances, min_active }
    }

    /// Returns `true` if enough instances are active to meet the minimum.
    pub fn is_healthy(&self) -> bool {
        self.active_count() >= self.min_active
    }

    /// Number of currently active instances.
    pub fn active_count(&self) -> usize {
        self.instances.iter().filter(|i| i.is_active).count()
    }

    /// Number of instances that are both active and attested.
    pub fn ready_count(&self) -> usize {
        self.instances.iter().filter(|i| i.is_ready()).count()
    }
}

/// Top-level coordinator for multi-TEE operations.
pub struct MultiTeeCoordinator {
    instances: Vec<TeeInstance>,
}

impl MultiTeeCoordinator {
    /// Create a coordinator with no instances.
    pub fn new() -> Self { Self { instances: Vec::new() } }

    /// Register a TEE instance with this coordinator.
    pub fn add_instance(&mut self, instance: TeeInstance) {
        self.instances.push(instance);
    }

    /// Total number of registered instances.
    pub fn instance_count(&self) -> usize { self.instances.len() }

    /// Returns the list of platforms among currently active instances.
    pub fn active_platforms(&self) -> Vec<TeePlatform> {
        self.instances.iter()
            .filter(|i| i.is_active)
            .map(|i| i.platform)
            .collect()
    }

    /// Returns the number of distinct platforms with active instances.
    pub fn platform_diversity(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        self.instances.iter()
            .filter(|i| i.is_active)
            .for_each(|i| { seen.insert(i.platform); });
        seen.len()
    }
}

impl Default for MultiTeeCoordinator {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_instance(platform: TeePlatform, active: bool) -> TeeInstance {
        TeeInstance {
            id: Hash256::ZERO,
            platform,
            validator_id: Hash256::ZERO,
            is_active: active,
            attestation: None,
        }
    }

    #[test]
    fn distributed_execution_threshold_check() {
        let instances = vec![
            make_instance(TeePlatform::IntelSgx, true),
            make_instance(TeePlatform::AmdSev, true),
            make_instance(TeePlatform::AwsNitro, true),
        ];
        let exec = DistributedTeeExecution::new(instances, 2);
        assert!(exec.meets_threshold());
        assert_eq!(exec.instance_count(), 3);
    }

    #[test]
    fn fault_tolerant_tee_health_check() {
        let instances = vec![
            make_instance(TeePlatform::IntelSgx, true),
            make_instance(TeePlatform::AmdSev, false),
            make_instance(TeePlatform::AwsNitro, true),
        ];
        let ft = FaultTolerantTee::new(instances, 2);
        assert!(ft.is_healthy());
        assert_eq!(ft.active_count(), 2);
    }

    #[test]
    fn coordinator_platform_diversity() {
        let mut coord = MultiTeeCoordinator::new();
        coord.add_instance(make_instance(TeePlatform::IntelSgx, true));
        coord.add_instance(make_instance(TeePlatform::IntelSgx, true)); // duplicate platform
        coord.add_instance(make_instance(TeePlatform::AmdSev, true));
        assert_eq!(coord.platform_diversity(), 2);
    }
}
