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
