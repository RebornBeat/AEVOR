//! Platform-agnostic code identity: **which** code the network permits to produce.
//!
//! Every TEE proves the same thing in its own format — *"this measured code ran in
//! a genuine enclave and produced exactly this output"*. What differs is the shape
//! of the measurement (Nitro PCRs, SGX MRENCLAVE/MRSIGNER, SEV-SNP MEASUREMENT,
//! PSA software components, Keystone enclave/SM hashes). This module is the one
//! place that answers the *network's* half of the question — *"and is that measured
//! code the code we all agreed to run?"* — for every platform.
//!
//! Each platform verifier returns a [`VerifiedEnclave`]: the cryptographically
//! verified measurements plus the bound application data. [`check_policy`] then
//! enforces the network's rules — the measurements are in the [`CodeRegistry`], the
//! bound data is what we expected, and the evidence is fresh. That is corruption
//! detection: instant, O(1) per block, no re-execution (doc 22).

use aevor_core::tee::TeePlatform;

use crate::{TeeError, TeeResult};

/// A cryptographically verified enclave, normalized across platforms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEnclave {
    /// Which TEE produced the evidence.
    pub platform: TeePlatform,
    /// Ordered, platform-defined code measurements. The order is fixed per
    /// platform so registry comparison is unambiguous:
    /// - Nitro: `[PCR0, PCR1, PCR2]` (+ `PCR8` when enforced)
    /// - SGX: `[MRENCLAVE, MRSIGNER]`
    /// - SEV-SNP: `[MEASUREMENT]`
    /// - `TrustZone` (PSA): one entry per software component measurement
    /// - Keystone: `[enclave_hash, sm_hash]`
    pub measurements: Vec<Vec<u8>>,
    /// Application data bound into the evidence (AEVOR: the `ExecutionAttestation`
    /// body), proving the enclave produced exactly this transition.
    pub user_data: Vec<u8>,
    /// Freshness nonce echoed from the attestation request, when the platform
    /// carries one.
    pub nonce: Vec<u8>,
    /// Evidence creation time in ms since the UNIX epoch, when the platform
    /// carries one (`None` for formats without a timestamp — freshness then rests
    /// on the nonce).
    pub timestamp_ms: Option<u64>,
}

/// One accepted enclave build: the measurements permitted to produce blocks on a
/// given platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeIdentity {
    /// Platform this identity applies to.
    pub platform: TeePlatform,
    /// The accepted measurements, in the platform's fixed order.
    pub measurements: Vec<Vec<u8>>,
}

impl CodeIdentity {
    /// An accepted identity for `platform` with the given ordered measurements.
    #[must_use]
    pub fn new(platform: TeePlatform, measurements: Vec<Vec<u8>>) -> Self {
        Self { platform, measurements }
    }
}

/// The network-agreed set of enclave builds permitted to produce blocks, across
/// every supported TEE platform. Updating it is a governance action (a protocol
/// upgrade): the measurement uniquely pins the exact code, including its economic
/// rules, so this subsumes a coarse protocol-version pin.
#[derive(Clone, Debug, Default)]
pub struct CodeRegistry {
    accepted: Vec<CodeIdentity>,
}

impl CodeRegistry {
    /// An empty registry (accepts nothing until identities are added).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit an enclave build.
    pub fn allow(&mut self, identity: CodeIdentity) {
        self.accepted.push(identity);
    }

    /// Number of permitted builds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    /// Whether nothing is permitted yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }

    /// Whether `measurements` on `platform` match a permitted build.
    ///
    /// A registered identity may list *fewer* measurements than the evidence
    /// carries: the registered ones must match position-for-position, so a network
    /// can pin (say) only `MRENCLAVE` and leave the rest unconstrained. An empty
    /// registered list matches nothing (fail closed).
    #[must_use]
    pub fn accepts(&self, platform: TeePlatform, measurements: &[Vec<u8>]) -> bool {
        self.accepted.iter().any(|id| {
            id.platform == platform
                && !id.measurements.is_empty()
                && id.measurements.len() <= measurements.len()
                && id.measurements.iter().zip(measurements).all(|(a, b)| a == b)
        })
    }
}

/// Enforce the network's policy on cryptographically verified evidence: the code
/// is permitted, the evidence binds the expected data, and it is fresh.
///
/// `now_ms` / `max_age_ms` are only applied when the platform's evidence carries a
/// timestamp; otherwise freshness rests on the caller's nonce, which is bound into
/// `user_data` for AEVOR (the attestation body commits to the transition).
///
/// # Errors
/// Returns [`TeeError::AttestationFailed`] if the bound data differs, the evidence
/// is stale, or the measurements are not in `registry`.
pub fn check_policy(
    enclave: &VerifiedEnclave,
    registry: &CodeRegistry,
    expected_user_data: &[u8],
    now_ms: u64,
    max_age_ms: u64,
) -> TeeResult<()> {
    if enclave.user_data != expected_user_data {
        return Err(TeeError::AttestationFailed {
            reason: "attestation does not bind the expected payload".to_string(),
        });
    }
    if let Some(ts) = enclave.timestamp_ms {
        if now_ms.saturating_sub(ts) > max_age_ms {
            return Err(TeeError::AttestationFailed {
                reason: "attestation evidence is stale".to_string(),
            });
        }
    }
    if registry.accepts(enclave.platform, &enclave.measurements) {
        Ok(())
    } else {
        Err(TeeError::AttestationFailed {
            reason: "enclave measurements are not in the accepted registry".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enclave(platform: TeePlatform, m: Vec<Vec<u8>>) -> VerifiedEnclave {
        VerifiedEnclave {
            platform,
            measurements: m,
            user_data: b"body".to_vec(),
            nonce: vec![1; 32],
            timestamp_ms: Some(1_000),
        }
    }

    #[test]
    fn registry_is_platform_scoped() {
        let mut r = CodeRegistry::new();
        assert!(r.is_empty());
        r.allow(CodeIdentity::new(TeePlatform::IntelSgx, vec![vec![1; 32], vec![2; 32]]));
        assert_eq!(r.len(), 1);
        assert!(r.accepts(TeePlatform::IntelSgx, &[vec![1; 32], vec![2; 32]]));
        // Same measurements on a DIFFERENT platform are not accepted.
        assert!(!r.accepts(TeePlatform::AmdSev, &[vec![1; 32], vec![2; 32]]));
        // Wrong measurement rejected.
        assert!(!r.accepts(TeePlatform::IntelSgx, &[vec![9; 32], vec![2; 32]]));
    }

    #[test]
    fn registry_allows_pinning_a_prefix_but_fails_closed_when_empty() {
        let mut r = CodeRegistry::new();
        // Pin only MRENCLAVE; MRSIGNER unconstrained.
        r.allow(CodeIdentity::new(TeePlatform::IntelSgx, vec![vec![1; 32]]));
        assert!(r.accepts(TeePlatform::IntelSgx, &[vec![1; 32], vec![0xAB; 32]]));
        assert!(!r.accepts(TeePlatform::IntelSgx, &[vec![2; 32], vec![0xAB; 32]]));
        // An empty registered identity matches nothing.
        let mut empty = CodeRegistry::new();
        empty.allow(CodeIdentity::new(TeePlatform::IntelSgx, vec![]));
        assert!(!empty.accepts(TeePlatform::IntelSgx, &[vec![1; 32]]));
        // An empty registry accepts nothing.
        assert!(!CodeRegistry::new().accepts(TeePlatform::IntelSgx, &[vec![1; 32]]));
    }

    #[test]
    fn policy_enforces_binding_freshness_and_registry() {
        let mut r = CodeRegistry::new();
        r.allow(CodeIdentity::new(TeePlatform::AmdSev, vec![vec![7; 48]]));
        let e = enclave(TeePlatform::AmdSev, vec![vec![7; 48]]);
        assert!(check_policy(&e, &r, b"body", 1_500, 1_000).is_ok());
        // Wrong bound data.
        assert!(check_policy(&e, &r, b"other", 1_500, 1_000).is_err());
        // Stale.
        assert!(check_policy(&e, &r, b"body", 99_000, 1_000).is_err());
        // Unregistered measurement.
        let bad = enclave(TeePlatform::AmdSev, vec![vec![9; 48]]);
        assert!(check_policy(&bad, &r, b"body", 1_500, 1_000).is_err());
    }

    #[test]
    fn platforms_without_timestamps_skip_the_staleness_check() {
        let mut r = CodeRegistry::new();
        r.allow(CodeIdentity::new(TeePlatform::RiscvKeystone, vec![vec![3; 64]]));
        let mut e = enclave(TeePlatform::RiscvKeystone, vec![vec![3; 64]]);
        e.timestamp_ms = None;
        // Even with a huge "now", no timestamp means no staleness rejection.
        assert!(check_policy(&e, &r, b"body", u64::MAX, 1).is_ok());
    }
}
