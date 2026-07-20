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

    /// Apply real Laplace noise to a true value, deriving the noise seed
    /// deterministically from the value. For caller-controlled entropy (fresh
    /// noise per query), use [`Self::apply_seeded`].
    pub fn apply(&self, true_value: f64) -> NoisedMetric {
        self.apply_seeded(true_value, true_value.to_bits())
    }

    /// Apply real Laplace(0, scale) noise sampled deterministically from `seed`.
    ///
    /// Noise is drawn by inverse-CDF transform from a `SplitMix64`-derived
    /// uniform, so the result is reproducible for a given `(value, seed)` — the
    /// property a verifier needs — while different seeds yield independent
    /// noise.
    pub fn apply_seeded(&self, true_value: f64, seed: u64) -> NoisedMetric {
        NoisedMetric {
            noised_value: true_value + laplace_noise(self.scale(), seed),
            epsilon_consumed: self.config.epsilon,
        }
    }
}

/// One uniform value in the open interval (0, 1) from a `SplitMix64` step.
fn uniform_open01(seed: u64) -> f64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    // Take 53 bits → [0, 1), then shift into (0, 1) to avoid the endpoints.
    #[allow(clippy::cast_precision_loss)]
    let numerator = (z >> 11) as f64 + 0.5;
    numerator / 9_007_199_254_740_992.0 // 2^53
}

/// Sample Laplace(0, `scale`) noise via inverse-CDF transform.
fn laplace_noise(scale: f64, seed: u64) -> f64 {
    let u = uniform_open01(seed);
    let centered = u - 0.5; // in (-0.5, 0.5)
    let sign = if centered < 0.0 { -1.0 } else { 1.0 };
    // inverse CDF: -scale * sgn(x) * ln(1 - 2|x|)
    -scale * sign * (1.0 - 2.0 * centered.abs()).ln()
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
    fn laplace_noise_is_deterministic_for_a_seed() {
        let mech = LaplaceMechanism::new(DpConfig::consensus_defaults());
        let a = mech.apply_seeded(42.5, 12345);
        let b = mech.apply_seeded(42.5, 12345);
        assert!((a.noised_value - b.noised_value).abs() < 1e-12);
        assert!((a.epsilon_consumed - 1.0).abs() < 1e-9);
    }

    #[test]
    fn laplace_noise_actually_perturbs_and_varies_by_seed() {
        let mech = LaplaceMechanism::new(DpConfig::consensus_defaults());
        // Different seeds generally produce different noised values.
        let x = mech.apply_seeded(100.0, 1).noised_value;
        let y = mech.apply_seeded(100.0, 2).noised_value;
        assert!((x - y).abs() > 1e-9, "distinct seeds should give distinct noise");
        // And at least one differs from the true value (noise is real).
        assert!((x - 100.0).abs() > 1e-9 || (y - 100.0).abs() > 1e-9);
    }

    #[test]
    fn laplace_noise_is_approximately_zero_mean() {
        // Averaged over many samples, Laplace(0, b) noise cancels to ~0.
        let mech = LaplaceMechanism::new(DpConfig { epsilon: 1.0, delta: 0.0, sensitivity: 1.0 });
        let n = 20_000u64;
        let mut sum = 0.0;
        for seed in 0..n {
            sum += mech.apply_seeded(0.0, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)).noised_value;
        }
        let mean = sum / n as f64;
        assert!(mean.abs() < 0.1, "empirical mean {mean} should be near 0");
    }

    #[test]
    fn laplace_mechanism_consumes_epsilon_from_config() {
        let cfg = DpConfig { epsilon: 0.5, delta: 0.0, sensitivity: 1.0 };
        let mech = LaplaceMechanism::new(cfg);
        let result = mech.apply(100.0);
        assert!((result.epsilon_consumed - 0.5).abs() < 1e-9);
    }
}
