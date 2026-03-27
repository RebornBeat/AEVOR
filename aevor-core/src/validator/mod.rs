//! # Validator Types
//!
//! Validator identity, status, capabilities, performance metrics, and commitments.
//! Validators are the backbone of AEVOR's PoU consensus — they provide both
//! consensus participation and TEE service infrastructure.

use serde::{Deserialize, Serialize};
use crate::primitives::{
    Address, BlockHeight, EpochNumber, Hash256, PublicKey,
    ValidatorId, ValidatorIndex, ValidatorWeight,
};
use crate::consensus::SecurityLevel;
use crate::tee::TeePlatform;

// ============================================================
// VALIDATOR ROLE
// ============================================================

/// The role a validator is currently serving.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidatorRole {
    /// Active consensus participant — votes on blocks, earns consensus rewards.
    Consensus,
    /// TEE service provider — provides confidential compute services.
    TeeService,
    /// Both consensus and TEE service simultaneously.
    Full,
    /// Archival validator — stores full history but doesn't vote.
    Archive,
    /// Candidate — registered but not yet in the active set.
    Candidate,
}

impl ValidatorRole {
    /// Returns `true` if this role participates in consensus.
    pub fn participates_in_consensus(&self) -> bool {
        matches!(self, Self::Consensus | Self::Full)
    }

    /// Returns `true` if this role provides TEE services.
    pub fn provides_tee_services(&self) -> bool {
        matches!(self, Self::TeeService | Self::Full)
    }
}

impl std::fmt::Display for ValidatorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Consensus => write!(f, "Consensus"),
            Self::TeeService => write!(f, "TeeService"),
            Self::Full => write!(f, "Full"),
            Self::Archive => write!(f, "Archive"),
            Self::Candidate => write!(f, "Candidate"),
        }
    }
}

// ============================================================
// VALIDATOR STATUS
// ============================================================

/// Current operational status of a validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Active and participating in all assigned roles.
    Active,
    /// Joining — in the process of entering the active set.
    Joining,
    /// Leaving — in the process of exiting the active set.
    Leaving,
    /// Inactive — registered but not currently participating.
    Inactive,
    /// Jailed — suspended due to slashing or Byzantine behavior.
    Jailed {
        /// Epoch when the jail term ends.
        release_epoch: u64,
    },
    /// Tombstoned — permanently removed (double-sign or critical violation).
    Tombstoned,
}

impl ValidatorStatus {
    /// Returns `true` if this validator can participate in consensus.
    pub fn can_vote(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns `true` if this validator is currently penalized.
    pub fn is_penalized(&self) -> bool {
        matches!(self, Self::Jailed { .. } | Self::Tombstoned)
    }

    /// Returns `true` if this validator is permanently removed.
    pub fn is_tombstoned(&self) -> bool {
        matches!(self, Self::Tombstoned)
    }
}

impl std::fmt::Display for ValidatorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Joining => write!(f, "Joining"),
            Self::Leaving => write!(f, "Leaving"),
            Self::Inactive => write!(f, "Inactive"),
            Self::Jailed { release_epoch } => write!(f, "Jailed(until epoch {release_epoch})"),
            Self::Tombstoned => write!(f, "Tombstoned"),
        }
    }
}

// ============================================================
// VALIDATOR INFO
// ============================================================

/// Complete information about a registered validator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator's unique identifier.
    pub id: ValidatorId,
    /// Validator's public signing key.
    pub signing_key: PublicKey,
    /// Address where staking rewards are sent.
    pub reward_address: Address,
    /// Address used for identity (separate from reward address).
    pub identity_address: Address,
    /// Current role in the network.
    pub role: ValidatorRole,
    /// Current operational status.
    pub status: ValidatorStatus,
    /// Index in the current validator set.
    pub index: ValidatorIndex,
    /// Voting weight proportional to stake.
    pub weight: ValidatorWeight,
    /// Epoch when this validator joined the active set.
    pub active_since_epoch: EpochNumber,
    /// TEE platforms this validator operates.
    pub tee_platforms: Vec<TeePlatform>,
    /// Human-readable display name (optional).
    pub display_name: Option<String>,
}

impl ValidatorInfo {
    /// Returns `true` if this validator can cast votes at the current state.
    pub fn is_voting(&self) -> bool {
        self.status.can_vote() && self.role.participates_in_consensus()
    }

    /// Returns `true` if this validator has any TEE platform configured.
    pub fn has_tee(&self) -> bool {
        !self.tee_platforms.is_empty()
    }
}

// ============================================================
// VALIDATOR CAPABILITIES
// ============================================================

/// Capabilities declared by a validator.
///
/// Validators declare what services they can provide so the network can
/// route requests appropriately. Claimed capabilities are verified through
/// TEE attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorCapabilities {
    /// Validator identifier these capabilities belong to.
    pub validator_id: ValidatorId,
    /// TEE platforms available on this validator.
    pub tee_platforms: Vec<TeePlatform>,
    /// TEE service types this validator can provide.
    pub tee_service_types: Vec<crate::tee::TeeServiceType>,
    /// Maximum security level this validator can attest to.
    pub max_security_level: SecurityLevel,
    /// Available TEE memory in bytes.
    pub available_tee_memory_bytes: usize,
    /// Maximum concurrent TEE executions supported.
    pub max_concurrent_tee: usize,
    /// Geographic region where this validator is located.
    pub region: crate::network::GeographicRegion,
    /// Network bandwidth capacity in Mbps.
    pub bandwidth_mbps: u32,
    /// Whether this validator supports ZK proof generation.
    pub supports_zk_proving: bool,
}

impl ValidatorCapabilities {
    /// Returns `true` if this validator can serve the requested service type.
    pub fn can_provide(&self, service: crate::tee::TeeServiceType) -> bool {
        self.tee_service_types.contains(&service)
    }

    /// Returns `true` if this validator can achieve the requested security level.
    pub fn meets_security_level(&self, level: SecurityLevel) -> bool {
        self.max_security_level >= level
    }
}

// ============================================================
// VALIDATOR PERFORMANCE
// ============================================================

/// Performance metrics for a validator over a given period.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorPerformance {
    /// Validator these metrics are for.
    pub validator_id: ValidatorId,
    /// Epoch these metrics cover.
    pub epoch: EpochNumber,
    /// Number of consensus rounds participated in.
    pub rounds_participated: u64,
    /// Number of consensus rounds the validator was expected to participate in.
    pub rounds_expected: u64,
    /// Number of blocks proposed by this validator.
    pub blocks_proposed: u64,
    /// Number of TEE service requests fulfilled.
    pub tee_requests_served: u64,
    /// Number of TEE service requests that failed.
    pub tee_requests_failed: u64,
    /// Average attestation latency in milliseconds.
    pub avg_attestation_latency_ms: u32,
    /// Number of slashing events in this period.
    pub slash_count: u32,
}

impl ValidatorPerformance {
    /// Compute the participation rate as a fraction (0.0–1.0).
    #[allow(clippy::cast_precision_loss)] // u64->f64 precision acceptable for participation metrics
    pub fn participation_rate(&self) -> f64 {
        if self.rounds_expected == 0 {
            return 1.0;
        }
        self.rounds_participated as f64 / self.rounds_expected as f64
    }

    /// Compute the TEE success rate as a fraction (0.0–1.0).
    #[allow(clippy::cast_precision_loss)] // u64->f64 precision acceptable for service metrics
    pub fn tee_success_rate(&self) -> f64 {
        let total = self.tee_requests_served + self.tee_requests_failed;
        if total == 0 {
            return 1.0;
        }
        self.tee_requests_served as f64 / total as f64
    }

    /// Returns `true` if this validator's performance meets minimum standards.
    pub fn meets_minimum_standards(&self) -> bool {
        self.participation_rate() >= 0.95 && self.slash_count == 0
    }
}

// ============================================================
// VALIDATOR COMMITMENT
// ============================================================

/// A cryptographic commitment from a validator for a specific block or round.
///
/// Validators commit to blocks before revealing their full vote, providing
/// binding commitments that prevent last-minute vote switching.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorCommitment {
    /// Validator making this commitment.
    pub validator_id: ValidatorId,
    /// What is being committed to.
    pub subject_hash: Hash256,
    /// The commitment value (hash of vote + randomness).
    pub commitment: Hash256,
    /// Block height this commitment is for.
    pub block_height: BlockHeight,
    /// Consensus round this commitment is for.
    pub consensus_round: u64,
    /// Validator's signature over the commitment.
    pub signature: crate::primitives::Signature,
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_role_participates_and_provides_tee() {
        assert!(ValidatorRole::Full.participates_in_consensus());
        assert!(ValidatorRole::Full.provides_tee_services());
    }

    #[test]
    fn consensus_role_does_not_provide_tee() {
        assert!(ValidatorRole::Consensus.participates_in_consensus());
        assert!(!ValidatorRole::Consensus.provides_tee_services());
    }

    #[test]
    fn jailed_cannot_vote() {
        let status = ValidatorStatus::Jailed { release_epoch: 100 };
        assert!(!status.can_vote());
        assert!(status.is_penalized());
    }

    #[test]
    fn active_can_vote() {
        assert!(ValidatorStatus::Active.can_vote());
        assert!(!ValidatorStatus::Active.is_penalized());
    }

    #[test]
    fn tombstoned_is_permanent() {
        assert!(ValidatorStatus::Tombstoned.is_tombstoned());
        assert!(ValidatorStatus::Tombstoned.is_penalized());
        assert!(!ValidatorStatus::Active.is_tombstoned());
    }

    #[test]
    fn validator_performance_participation_rate() {
        let perf = ValidatorPerformance {
            validator_id: Hash256::ZERO,
            epoch: EpochNumber::GENESIS,
            rounds_participated: 95,
            rounds_expected: 100,
            blocks_proposed: 5,
            tee_requests_served: 100,
            tee_requests_failed: 0,
            avg_attestation_latency_ms: 50,
            slash_count: 0,
        };
        assert!((perf.participation_rate() - 0.95).abs() < 1e-9);
        assert!(perf.meets_minimum_standards());
    }

    #[test]
    fn validator_performance_below_minimum() {
        let perf = ValidatorPerformance {
            validator_id: Hash256::ZERO,
            epoch: EpochNumber::GENESIS,
            rounds_participated: 80,
            rounds_expected: 100,
            blocks_proposed: 0,
            tee_requests_served: 0,
            tee_requests_failed: 0,
            avg_attestation_latency_ms: 500,
            slash_count: 1,
        };
        assert!(!perf.meets_minimum_standards());
    }

    #[test]
    fn capabilities_can_provide_service() {
        let caps = ValidatorCapabilities {
            validator_id: Hash256::ZERO,
            tee_platforms: vec![TeePlatform::IntelSgx],
            tee_service_types: vec![crate::tee::TeeServiceType::Compute],
            max_security_level: SecurityLevel::Full,
            available_tee_memory_bytes: 128 * 1024 * 1024,
            max_concurrent_tee: 4,
            region: crate::network::GeographicRegion::NorthAmerica,
            bandwidth_mbps: 1000,
            supports_zk_proving: true,
        };
        assert!(caps.can_provide(crate::tee::TeeServiceType::Compute));
        assert!(!caps.can_provide(crate::tee::TeeServiceType::Bridge));
    }
}
