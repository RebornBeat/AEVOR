//! Configuration validation.

use crate::{AevorConfig, ConfigError, ConfigResult};

/// Result of a configuration validation pass.
#[derive(Clone, Debug)]
pub struct ValidationResult {
    /// Whether the configuration is valid.
    pub is_valid: bool,
    /// Validation errors (if any).
    pub errors: Vec<ConfigValidationError>,
    /// Validation warnings (valid but potentially misconfigured).
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Create a passing validation result.
    pub fn valid() -> Self {
        Self { is_valid: true, errors: vec![], warnings: vec![] }
    }
    /// Create a failing validation result with a single error.
    pub fn with_error(error: ConfigValidationError) -> Self {
        Self { is_valid: false, errors: vec![error], warnings: vec![] }
    }
}

/// A specific configuration validation error.
#[derive(Clone, Debug, thiserror::Error)]
#[error("config validation: {field}: {message}")]
pub struct ConfigValidationError {
    /// The configuration field that failed validation.
    pub field: String,
    /// Human-readable description of the validation failure.
    pub message: String,
}

impl ConfigValidationError {
    /// Create a new validation error.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self { field: field.into(), message: message.into() }
    }
}

/// Trait for types that can validate themselves.
pub trait ConfigValidation {
    /// Validate this configuration and return a result.
    fn validate_config(&self) -> ValidationResult;
}

impl ConfigValidation for AevorConfig {
    fn validate_config(&self) -> ValidationResult {
        match validate_full_config(self) {
            Ok(()) => ValidationResult::valid(),
            Err(e) => ValidationResult::with_error(
                ConfigValidationError::new("config", e.to_string())
            ),
        }
    }
}

/// Validate the complete `AevorConfig`.
///
/// # Errors
/// Returns a `ConfigError` if any subsystem configuration is structurally
/// invalid — e.g. reward shares don't sum to 10 000 bps, proposal timeout
/// exceeds round timeout, or `max_peers` is zero.
pub fn validate_full_config(config: &AevorConfig) -> ConfigResult<()> {
    validate_economics(config)?;
    validate_consensus(config)?;
    validate_network(config)?;
    Ok(())
}

fn validate_economics(config: &AevorConfig) -> ConfigResult<()> {
    let r = &config.economics.reward;
    let total_bps = r.validator_share_bps + r.tee_service_share_bps + r.treasury_share_bps;
    if total_bps != 10_000 {
        return Err(ConfigError::Conflict {
            description: format!(
                "reward shares must sum to 10000 bps (100%), got {total_bps}"
            ),
        });
    }
    Ok(())
}

fn validate_consensus(config: &AevorConfig) -> ConfigResult<()> {
    let t = &config.consensus.round_timing;
    if t.proposal_timeout_ms >= t.round_timeout_ms {
        return Err(ConfigError::OutOfRange {
            field: "consensus.round_timing.proposal_timeout_ms".into(),
            value: t.proposal_timeout_ms.to_string(),
            constraint: format!("must be < round_timeout_ms ({})", t.round_timeout_ms),
        });
    }
    Ok(())
}

fn validate_network(config: &AevorConfig) -> ConfigResult<()> {
    if config.network.max_peers == 0 {
        return Err(ConfigError::OutOfRange {
            field: "network.max_peers".into(),
            value: "0".into(),
            constraint: "must be > 0".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defaults;

    #[test]
    fn valid_result_has_no_errors() {
        let r = ValidationResult::valid();
        assert!(r.is_valid);
        assert!(r.errors.is_empty());
    }

    #[test]
    fn invalid_result_has_error() {
        let e = ConfigValidationError::new("my.field", "bad value");
        let r = ValidationResult::with_error(e);
        assert!(!r.is_valid);
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].to_string().contains("my.field"));
    }

    #[test]
    fn config_validation_error_formats_field_and_message() {
        let e = ConfigValidationError::new("network.max_peers", "must be > 0");
        assert!(e.to_string().contains("network.max_peers"));
        assert!(e.to_string().contains("must be > 0"));
    }

    #[test]
    fn mainnet_defaults_pass_full_validation() {
        let cfg = defaults::mainnet_defaults();
        assert!(validate_full_config(&cfg).is_ok());
    }

    #[test]
    fn zero_max_peers_fails_validation() {
        let mut cfg = defaults::mainnet_defaults();
        cfg.network.max_peers = 0;
        assert!(validate_full_config(&cfg).is_err());
    }

    #[test]
    fn mismatched_reward_bps_fails_validation() {
        let mut cfg = defaults::mainnet_defaults();
        // Break the invariant: shares won't sum to 10 000
        cfg.economics.reward.validator_share_bps = 9_000;
        cfg.economics.reward.tee_service_share_bps = 500;
        cfg.economics.reward.treasury_share_bps = 400; // 9 900 != 10 000
        let result = validate_full_config(&cfg);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("10000"));
    }

    #[test]
    fn validate_config_trait_returns_valid_for_defaults() {
        use super::ConfigValidation;
        let cfg = defaults::mainnet_defaults();
        let result = cfg.validate_config();
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }
}
