//! Security Level Accelerator — progressive finality configuration.

use serde::{Deserialize, Serialize};
pub use aevor_core::consensus::SecurityLevel;

/// Full configuration for a security level.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityLevelConfig {
    pub level: SecurityLevel,
    pub min_participation_pct: u8,
    pub max_confirmation_ms: u64,
    pub requires_tee: bool,
}

impl SecurityLevelConfig {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    // min_participation() returns values in [0.0, 1.0] so * 100.0 ∈ [0, 100] — safe to u8
    pub fn for_level(level: SecurityLevel) -> Self {
        Self {
            level,
            min_participation_pct: (level.min_participation() * 100.0) as u8,
            max_confirmation_ms: level.max_confirmation_ms(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::ValidatorWeight;

    #[test]
    fn security_level_config_for_level_participation_ordered() {
        let minimal = SecurityLevelConfig::for_level(SecurityLevel::Minimal);
        let full = SecurityLevelConfig::for_level(SecurityLevel::Full);
        // Full requires higher participation than Minimal
        assert!(full.min_participation_pct > minimal.min_participation_pct);
    }

    #[test]
    fn security_level_config_for_level_timing_ordered() {
        let minimal = SecurityLevelConfig::for_level(SecurityLevel::Minimal);
        let full = SecurityLevelConfig::for_level(SecurityLevel::Full);
        // Full allows more time than Minimal
        assert!(full.max_confirmation_ms >= minimal.max_confirmation_ms);
    }

    #[test]
    fn accelerator_config_for_returns_matching_level() {
        let acc = SecurityLevelAccelerator::new();
        let cfg = acc.config_for(SecurityLevel::Basic);
        assert_eq!(cfg.level, SecurityLevel::Basic);
    }

    #[test]
    fn accelerator_all_levels_accessible() {
        let acc = SecurityLevelAccelerator::default();
        for level in [SecurityLevel::Minimal, SecurityLevel::Basic, SecurityLevel::Strong, SecurityLevel::Full] {
            let cfg = acc.config_for(level);
            assert_eq!(cfg.level, level);
            assert!(cfg.min_participation_pct > 0);
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
}
