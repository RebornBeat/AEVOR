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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::EpochNumber;

    fn ctx(validators: usize) -> ValidationContext {
        ValidationContext { network: "testnet".into(), epoch: EpochNumber(1), active_validators: validators }
    }

    fn rule(id: &str) -> ValidationRule {
        ValidationRule { id: id.into(), description: "test rule".into(), severity: 5 }
    }

    #[test]
    fn validation_result_ok_all_passed() {
        let r = ValidationResult::ok();
        assert!(r.all_passed);
        assert_eq!(r.pass_count(), 0); // no checks at all
    }

    #[test]
    fn validation_result_failed_not_all_passed() {
        let check = SecurityCheck { rule: rule("r1"), passed: false, details: None };
        let r = ValidationResult::failed(check);
        assert!(!r.all_passed);
        assert_eq!(r.pass_count(), 0);
    }

    #[test]
    fn pass_count_counts_passed_checks() {
        let r = ValidationResult {
            checks: vec![
                SecurityCheck { rule: rule("r1"), passed: true, details: None },
                SecurityCheck { rule: rule("r2"), passed: false, details: None },
                SecurityCheck { rule: rule("r3"), passed: true, details: None },
            ],
            all_passed: false,
        };
        assert_eq!(r.pass_count(), 2);
    }

    #[test]
    fn infrastructure_policy_default_requires_tee_and_distribution() {
        let p = InfrastructureSecurityPolicy::default();
        assert!(p.require_tee);
        assert!(p.require_geographic_distribution);
        assert!(p.min_validator_count > 0);
    }

    #[test]
    fn security_validator_passes_with_sufficient_validators() {
        let pol = InfrastructureSecurityPolicy { min_validator_count: 4, ..Default::default() };
        let v = SecurityValidator::new(pol);
        let r = v.validate(&ctx(10));
        assert!(r.all_passed);
    }

    #[test]
    fn security_validator_fails_with_insufficient_validators() {
        let pol = InfrastructureSecurityPolicy { min_validator_count: 10, ..Default::default() };
        let v = SecurityValidator::new(pol);
        let r = v.validate(&ctx(3));
        assert!(!r.all_passed);
        assert!(r.checks[0].details.is_some());
    }
}
