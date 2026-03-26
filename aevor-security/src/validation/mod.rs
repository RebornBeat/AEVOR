//! Infrastructure security validation.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationRule { pub id: String, pub description: String, pub severity: u8 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityCheck { pub rule: ValidationRule, pub passed: bool, pub details: Option<String> }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationResult { pub checks: Vec<SecurityCheck>, pub all_passed: bool }

impl ValidationResult {
    pub fn ok() -> Self { Self { checks: Vec::new(), all_passed: true } }
    pub fn failed(check: SecurityCheck) -> Self { Self { checks: vec![check], all_passed: false } }
    pub fn pass_count(&self) -> usize { self.checks.iter().filter(|c| c.passed).count() }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InfrastructureSecurityPolicy {
    pub require_tee: bool,
    pub min_validator_count: usize,
    pub require_geographic_distribution: bool,
}
impl Default for InfrastructureSecurityPolicy {
    fn default() -> Self { Self { require_tee: true, min_validator_count: 4, require_geographic_distribution: true } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationContext {
    pub network: String,
    pub epoch: aevor_core::primitives::EpochNumber,
    pub active_validators: usize,
}

pub struct SecurityValidator { policy: InfrastructureSecurityPolicy }
impl SecurityValidator {
    pub fn new(policy: InfrastructureSecurityPolicy) -> Self { Self { policy } }
    pub fn validate(&self, ctx: &ValidationContext) -> ValidationResult {
        let passed = ctx.active_validators >= self.policy.min_validator_count;
        if passed { ValidationResult::ok() }
        else {
            ValidationResult::failed(SecurityCheck {
                rule: ValidationRule { id: "min-validators".into(), description: "Minimum validator count".into(), severity: 10 },
                passed: false,
                details: Some(format!("Need {}, have {}", self.policy.min_validator_count, ctx.active_validators)),
            })
        }
    }
}
