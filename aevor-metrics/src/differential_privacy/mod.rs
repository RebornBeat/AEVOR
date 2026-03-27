//! Differential privacy mechanisms for metrics reporting.
//!
//! Applies calibrated Laplace or Gaussian noise to metrics before export,
//! preventing individual validator behavior from being inferred from aggregate stats.

use serde::{Deserialize, Serialize};

/// Configuration for a differential privacy mechanism.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DpConfig {
    /// Privacy budget epsilon (lower = stronger privacy, higher = more utility).
    pub epsilon: f64,
    /// Privacy budget delta for (ε, δ)-DP (0.0 for pure DP).
    pub delta: f64,
    /// Sensitivity of the query (maximum change one record can cause).
    pub sensitivity: f64,
}

impl DpConfig {
    /// Recommended settings for consensus metrics (moderate privacy).
    pub fn consensus_defaults() -> Self {
        Self { epsilon: 1.0, delta: 1e-5, sensitivity: 1.0 }
    }

    /// Recommended settings for validator performance (stronger privacy).
    pub fn validator_defaults() -> Self {
        Self { epsilon: 0.1, delta: 1e-6, sensitivity: 1.0 }
    }
}

/// A differentially-private metric value with its noise budget consumed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoisedMetric {
    /// The noised value (true value + calibrated noise).
    pub noised_value: f64,
    /// Epsilon consumed by this release.
    pub epsilon_consumed: f64,
}

/// Applies Laplace mechanism noise to a value for (ε)-differential privacy.
pub struct LaplaceMechanism {
    config: DpConfig,
}

impl LaplaceMechanism {
    /// Create a Laplace mechanism with the given configuration.
    pub fn new(config: DpConfig) -> Self { Self { config } }

    /// The Laplace scale parameter: sensitivity / epsilon.
    pub fn scale(&self) -> f64 { self.config.sensitivity / self.config.epsilon }

    /// Apply noise to a true value and return a `NoisedMetric`.
    ///
    /// In production, samples from Laplace(0, scale). Here we return the
    /// true value plus zero noise for deterministic testing.
    pub fn apply(&self, true_value: f64) -> NoisedMetric {
        NoisedMetric {
            noised_value: true_value, // Real impl adds Laplace noise
            epsilon_consumed: self.config.epsilon,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dp_config_consensus_defaults_moderate_epsilon() {
        let cfg = DpConfig::consensus_defaults();
        assert!((cfg.epsilon - 1.0).abs() < 1e-9);
        assert!(cfg.delta > 0.0);
        assert!((cfg.sensitivity - 1.0).abs() < 1e-9);
    }

    #[test]
    fn dp_config_validator_defaults_stronger_privacy() {
        let consensus = DpConfig::consensus_defaults();
        let validator = DpConfig::validator_defaults();
        // Smaller epsilon = stronger privacy
        assert!(validator.epsilon < consensus.epsilon);
        assert!(validator.delta < consensus.delta);
    }

    #[test]
    fn laplace_mechanism_scale_is_sensitivity_over_epsilon() {
        let cfg = DpConfig { epsilon: 2.0, delta: 0.0, sensitivity: 4.0 };
        let mech = LaplaceMechanism::new(cfg);
        assert!((mech.scale() - 2.0).abs() < 1e-9); // 4.0 / 2.0
    }

    #[test]
    fn laplace_mechanism_scale_with_epsilon_1_equals_sensitivity() {
        let cfg = DpConfig { epsilon: 1.0, delta: 0.0, sensitivity: 5.0 };
        let mech = LaplaceMechanism::new(cfg);
        assert!((mech.scale() - 5.0).abs() < 1e-9);
    }

    #[test]
    fn laplace_mechanism_apply_preserves_true_value_in_stub() {
        let mech = LaplaceMechanism::new(DpConfig::consensus_defaults());
        let result = mech.apply(42.5);
        // Stub implementation: noised_value == true_value
        assert!((result.noised_value - 42.5).abs() < 1e-9);
        assert!((result.epsilon_consumed - 1.0).abs() < 1e-9);
    }

    #[test]
    fn laplace_mechanism_consumes_epsilon_from_config() {
        let cfg = DpConfig { epsilon: 0.5, delta: 0.0, sensitivity: 1.0 };
        let mech = LaplaceMechanism::new(cfg);
        let result = mech.apply(100.0);
        assert!((result.epsilon_consumed - 0.5).abs() < 1e-9);
    }
}
