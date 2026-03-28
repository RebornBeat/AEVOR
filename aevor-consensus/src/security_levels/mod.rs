//! Security Level Accelerator — progressive finality configuration.
//!
//! The confirmation time values in this module are **current-network estimates**
//! based on typical latency and validator set size. They are NOT performance
//! ceilings — the architecture imposes no artificial throughput constraint.
//! Actual confirmation often occurs faster, and will continue to improve as
//! network infrastructure, hardware, and validator counts grow.

use serde::{Deserialize, Serialize};
pub use aevor_core::consensus::SecurityLevel;

/// Full configuration for a security level.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityLevelConfig {
    pub level: SecurityLevel,
    pub min_participation_pct: u8,
    /// Typical confirmation time estimate in milliseconds for current networks.
    /// This is **not a hard limit** — actual confirmation may be faster.
    pub typical_confirmation_ms_estimate: u64,
    pub requires_tee: bool,
}

impl SecurityLevelConfig {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    // min_participation() returns values in [0.0, 1.0] so * 100.0 ∈ [0, 100] — safe to u8
    pub fn for_level(level: SecurityLevel) -> Self {
        Self {
            level,
            min_participation_pct: (level.min_participation() * 100.0) as u8,
            typical_confirmation_ms_estimate: level.typical_confirmation_ms_estimate(),
            requires_tee: true,
        }
    }
}

/// The Security Level Accelerator — enables progressive finality.
pub struct SecurityLevelAccelerator {
    configs: [SecurityLevelConfig; 4],
}

impl SecurityLevelAccelerator {
    pub fn new() -> Self {
        Self {
            configs: [
                SecurityLevelConfig::for_level(SecurityLevel::Minimal),
                SecurityLevelConfig::for_level(SecurityLevel::Basic),
                SecurityLevelConfig::for_level(SecurityLevel::Strong),
                SecurityLevelConfig::for_level(SecurityLevel::Full),
            ],
        }
    }

    pub fn config_for(&self, level: SecurityLevel) -> &SecurityLevelConfig {
        &self.configs[level as usize]
    }
}

impl Default for SecurityLevelAccelerator {
    fn default() -> Self { Self::new() }
}

/// Minimal security (2–3% validators, 20–50ms).
pub struct MinimalSecurity;
/// Basic security (10–20%, 100–200ms).
pub struct BasicSecurity;
/// Strong security (>33%, 500–800ms, BFT).
pub struct StrongSecurity;
/// Full security (>67%, <1s).
pub struct FullSecurity;

/// Validator participation data for a round.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorParticipation {
    pub participating: Vec<aevor_core::primitives::ValidatorId>,
    pub total_weight: aevor_core::primitives::ValidatorWeight,
    pub participating_weight: aevor_core::primitives::ValidatorWeight,
}

impl ValidatorParticipation {
    #[allow(clippy::cast_precision_loss)] // weight ratios: precision loss is acceptable
    pub fn fraction(&self) -> f64 {
        if self.total_weight.as_u64() == 0 { return 0.0; }
        self.participating_weight.as_u64() as f64 / self.total_weight.as_u64() as f64
    }
}

/// Minimum participation threshold for a security level.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipationThreshold {
    pub level: SecurityLevel,
    pub min_fraction: f64,
    pub min_validator_count: usize,
}

/// A condition that triggers automatic security level escalation.
///
/// Applications define escalation triggers so the infrastructure can
/// automatically provide stronger security for higher-value or higher-risk
/// operations without requiring explicit application-level coordination.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscalationTrigger {
    /// Amount threshold in nanoAEVOR above which to escalate.
    pub value_threshold_nano: Option<u128>,
    /// Security level to escalate to when the trigger fires.
    pub escalate_to: SecurityLevel,
    /// Human-readable description of this trigger's purpose.
    pub description: String,
}

impl EscalationTrigger {
    /// Create a value-based escalation trigger.
    pub fn on_value(threshold_nano: u128, to: SecurityLevel) -> Self {
        Self {
            value_threshold_nano: Some(threshold_nano),
            escalate_to: to,
            description: format!("escalate to {to} when value > {threshold_nano} nAEVOR"),
        }
    }

    /// Evaluate whether this trigger fires for the given transaction value.
    pub fn fires_for_value(&self, value_nano: u128) -> bool {
        self.value_threshold_nano.map_or(false, |t| value_nano > t)
    }
}

/// Security level policy for an application or deployment.
///
/// Defines a base security level, escalation triggers for high-value operations,
/// and optional degradation to lower levels under specified conditions.
/// All transitions are seamless — applications receive consistent interfaces
/// regardless of the active security level.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityLevelPolicy {
    /// Default security level for routine operations.
    pub base_level: SecurityLevel,
    /// Escalation triggers — conditions that automatically raise security.
    pub escalation_triggers: Vec<EscalationTrigger>,
    /// Whether automatic degradation is permitted under high load.
    pub allow_degradation: bool,
    /// Minimum level below which degradation must not go.
    pub degradation_floor: SecurityLevel,
}

impl SecurityLevelPolicy {
    /// Create a policy with a fixed base level and no escalation.
    pub fn fixed(level: SecurityLevel) -> Self {
        Self {
            base_level: level,
            escalation_triggers: vec![],
            allow_degradation: false,
            degradation_floor: level,
        }
    }

    /// Evaluate the effective security level for a given transaction value.
    ///
    /// Returns the highest level triggered by the given value, or `base_level`
    /// if no escalation trigger fires.
    pub fn effective_level_for_value(&self, value_nano: u128) -> SecurityLevel {
        self.escalation_triggers.iter()
            .filter(|t| t.fires_for_value(value_nano))
            .map(|t| t.escalate_to)
            .max_by_key(|&l| l as u8)
            .unwrap_or(self.base_level)
    }
}

impl Default for SecurityLevelPolicy {
    fn default() -> Self { Self::fixed(SecurityLevel::Basic) }
}

/// Topology score for a validator — used by the security level accelerator
/// to select validators that optimize both security coverage and coordination
/// efficiency.
///
/// This bridges the consensus layer (validator weights) and the network layer
/// (topology-aware routing) to enable intelligent validator selection that
/// minimizes confirmation latency while maintaining geographic diversity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorTopologyScore {
    /// Validator identifier.
    pub validator_id: aevor_core::primitives::ValidatorId,
    /// Estimated round-trip latency to this validator in milliseconds.
    /// Lower is better for coordination efficiency. Hardware-dependent — will
    /// decrease as network infrastructure improves.
    pub estimated_rtt_ms: u32,
    /// Geographic region code (continent-level granularity).
    pub region: String,
    /// TEE platform this validator operates.
    pub tee_platform: aevor_core::tee::TeePlatform,
    /// Historical reliability score [0.0, 1.0] — 1.0 = perfect uptime.
    pub reliability_score: f64,
}

impl ValidatorTopologyScore {
    /// Composite score for validator selection. Higher is better.
    ///
    /// Balances low latency with high reliability. The formula is:
    /// `reliability * (1000.0 / (1.0 + rtt_ms))` — reliability-weighted
    /// inverse latency, giving a higher score to reliable low-latency validators.
    #[allow(clippy::cast_precision_loss)]
    pub fn composite_score(&self) -> f64 {
        self.reliability_score * (1000.0 / (1.0 + self.estimated_rtt_ms as f64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, ValidatorWeight};
    use aevor_core::tee::TeePlatform;

    #[test]
    fn security_level_config_for_level_participation_ordered() {
        let minimal = SecurityLevelConfig::for_level(SecurityLevel::Minimal);
        let full = SecurityLevelConfig::for_level(SecurityLevel::Full);
        assert!(full.min_participation_pct > minimal.min_participation_pct);
    }

    #[test]
    fn security_level_config_estimate_ordering_reflects_broader_consensus() {
        // Higher security levels consult more validators — current-network estimates
        // are higher. Estimates only, not hard limits — real confirmation may be
        // faster as network infrastructure improves.
        let minimal = SecurityLevelConfig::for_level(SecurityLevel::Minimal);
        let full = SecurityLevelConfig::for_level(SecurityLevel::Full);
        assert!(full.typical_confirmation_ms_estimate >= minimal.typical_confirmation_ms_estimate);
    }

    #[test]
    fn accelerator_config_for_returns_matching_level() {
        let acc = SecurityLevelAccelerator::new();
        let cfg = acc.config_for(SecurityLevel::Basic);
        assert_eq!(cfg.level, SecurityLevel::Basic);
    }

    #[test]
    fn accelerator_all_levels_require_tee() {
        let acc = SecurityLevelAccelerator::default();
        for level in [SecurityLevel::Minimal, SecurityLevel::Basic, SecurityLevel::Strong, SecurityLevel::Full] {
            let cfg = acc.config_for(level);
            assert_eq!(cfg.level, level);
            assert!(cfg.min_participation_pct > 0);
            assert!(cfg.requires_tee, "all security levels require TEE attestation");
        }
    }

    #[test]
    fn validator_participation_fraction_zero_when_no_weight() {
        let vp = ValidatorParticipation {
            participating: vec![],
            total_weight: ValidatorWeight::ZERO,
            participating_weight: ValidatorWeight::ZERO,
        };
        assert_eq!(vp.fraction(), 0.0);
    }

    #[test]
    fn validator_participation_fraction_half() {
        let vp = ValidatorParticipation {
            participating: vec![],
            total_weight: ValidatorWeight::from_u64(100),
            participating_weight: ValidatorWeight::from_u64(50),
        };
        assert!((vp.fraction() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn validator_participation_full() {
        let vp = ValidatorParticipation {
            participating: vec![],
            total_weight: ValidatorWeight::from_u64(100),
            participating_weight: ValidatorWeight::from_u64(100),
        };
        assert!((vp.fraction() - 1.0).abs() < 1e-9);
    }

    // ── SecurityLevelPolicy — escalation/degradation ──────────────────────

    #[test]
    fn policy_fixed_returns_base_level_always() {
        let policy = SecurityLevelPolicy::fixed(SecurityLevel::Basic);
        assert_eq!(policy.effective_level_for_value(0), SecurityLevel::Basic);
        assert_eq!(policy.effective_level_for_value(u128::MAX), SecurityLevel::Basic);
    }

    #[test]
    fn policy_escalation_trigger_fires_on_high_value() {
        let mut policy = SecurityLevelPolicy::fixed(SecurityLevel::Basic);
        policy.escalation_triggers.push(
            EscalationTrigger::on_value(1_000_000_000, SecurityLevel::Strong)
        );
        // Below threshold — stays at base
        assert_eq!(policy.effective_level_for_value(999_999_999), SecurityLevel::Basic);
        // Above threshold — escalates
        assert_eq!(policy.effective_level_for_value(1_000_000_001), SecurityLevel::Strong);
    }

    #[test]
    fn policy_multiple_triggers_returns_highest_applicable() {
        let mut policy = SecurityLevelPolicy::fixed(SecurityLevel::Minimal);
        policy.escalation_triggers.push(EscalationTrigger::on_value(100, SecurityLevel::Basic));
        policy.escalation_triggers.push(EscalationTrigger::on_value(1_000, SecurityLevel::Strong));
        policy.escalation_triggers.push(EscalationTrigger::on_value(100_000, SecurityLevel::Full));
        // Only first trigger fires
        assert_eq!(policy.effective_level_for_value(500), SecurityLevel::Basic);
        // First and second fire — returns highest (Strong)
        assert_eq!(policy.effective_level_for_value(5_000), SecurityLevel::Strong);
        // All fire — returns Full
        assert_eq!(policy.effective_level_for_value(200_000), SecurityLevel::Full);
    }

    #[test]
    fn policy_no_degradation_by_default_with_fixed() {
        let policy = SecurityLevelPolicy::fixed(SecurityLevel::Strong);
        assert!(!policy.allow_degradation);
        assert_eq!(policy.degradation_floor, SecurityLevel::Strong);
    }

    #[test]
    fn escalation_trigger_fires_strictly_above_threshold() {
        let t = EscalationTrigger::on_value(1000, SecurityLevel::Full);
        assert!(!t.fires_for_value(1000)); // exactly at threshold — does NOT fire
        assert!(t.fires_for_value(1001));  // strictly above — fires
        assert!(!t.fires_for_value(999));  // below — does not fire
    }

    // ── ValidatorTopologyScore ────────────────────────────────────────────

    #[test]
    fn topology_score_composite_higher_for_low_latency_high_reliability() {
        let fast_reliable = ValidatorTopologyScore {
            validator_id: Hash256([1u8; 32]),
            estimated_rtt_ms: 10,
            region: "EU".into(),
            tee_platform: TeePlatform::IntelSgx,
            reliability_score: 0.99,
        };
        let slow_unreliable = ValidatorTopologyScore {
            validator_id: Hash256([2u8; 32]),
            estimated_rtt_ms: 500,
            region: "AS".into(),
            tee_platform: TeePlatform::AmdSev,
            reliability_score: 0.70,
        };
        assert!(fast_reliable.composite_score() > slow_unreliable.composite_score());
    }

    #[test]
    fn topology_score_zero_reliability_gives_zero_composite() {
        let v = ValidatorTopologyScore {
            validator_id: Hash256([1u8; 32]),
            estimated_rtt_ms: 1,
            region: "NA".into(),
            tee_platform: TeePlatform::ArmTrustZone,
            reliability_score: 0.0,
        };
        assert_eq!(v.composite_score(), 0.0);
    }

    #[test]
    fn topology_score_platform_diversity_trackable() {
        let platforms = [
            TeePlatform::IntelSgx,
            TeePlatform::AmdSev,
            TeePlatform::ArmTrustZone,
            TeePlatform::RiscvKeystone,
            TeePlatform::AwsNitro,
        ];
        let scores: Vec<ValidatorTopologyScore> = platforms.iter().enumerate()
            .map(|(i, &p)| ValidatorTopologyScore {
                validator_id: Hash256([i as u8; 32]),
                estimated_rtt_ms: 50,
                region: "Global".into(),
                tee_platform: p,
                reliability_score: 0.95,
            })
            .collect();
        // All 5 platforms can be represented — no fixed-size constraint
        assert_eq!(scores.len(), 5);
        let unique_platforms: std::collections::HashSet<_> = scores.iter()
            .map(|s| s.tee_platform as u8)
            .collect();
        assert_eq!(unique_platforms.len(), 5);
    }
}
