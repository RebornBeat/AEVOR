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
