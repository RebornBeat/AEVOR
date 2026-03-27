//! # AEVOR Security: Multi-TEE Security Validation
//!
//! `aevor-security` provides comprehensive security coordination across AEVOR's
//! infrastructure, implementing threat detection, attack mitigation, cross-platform
//! security consistency, and privacy-preserving network intelligence.
//!
//! ## Security Architecture Principles
//!
//! **Mathematical Security Through Verification**: Security guarantees are mathematically
//! provable through TEE attestation and cryptographic verification, not probabilistic
//! assessments requiring multiple confirmations or economic assumptions.
//!
//! **Privacy-Aware Threat Detection**: Anomaly detection identifies network attacks and
//! infrastructure threats without creating surveillance capabilities or compromising
//! user privacy. The security layer never builds user behavioral profiles.
//!
//! **Defense Without Centralization**: Security coordination happens through decentralized
//! validator infrastructure. No centralized security services, no external threat
//! intelligence subscriptions, no third-party dependencies.
//!
//! **Cross-Platform Consistency**: Identical security guarantees across Intel SGX,
//! AMD SEV, ARM `TrustZone`, RISC-V Keystone, and AWS Nitro Enclaves through behavioral
//! standardization and cross-platform verification protocols.
//!
//! ## Scope
//!
//! This crate covers infrastructure security: validator authentication, TEE integrity,
//! network attack detection, and slashing coordination. Application-layer security
//! (smart contract access control, privacy policies) belongs in application crates.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Security validation engine: cross-component security rule enforcement.
pub mod validation;

/// Threat detection: privacy-preserving anomaly detection for infrastructure threats.
pub mod threat_detection;

/// Attack mitigation: automated responses to detected infrastructure attacks.
pub mod mitigation;

/// Cross-platform verification: behavioral consistency validation across TEE platforms.
pub mod cross_platform;

/// Byzantine detection: extended Byzantine behavior identification and evidence collection.
pub mod byzantine;

/// Validator authentication: TEE-backed validator identity verification.
pub mod auth;

/// Network security: DDoS protection, Sybil resistance, eclipse attack prevention.
pub mod network_security;

/// TEE integrity: continuous enclave integrity monitoring and compromise detection.
pub mod tee_integrity;

/// Security audit: immutable audit trail without user surveillance.
pub mod audit;

/// Slashing coordination: evidence verification and penalty execution coordination.
pub mod slashing;

/// Security metrics: attack frequency, mitigation effectiveness, threat landscape.
pub mod metrics;

// ============================================================
// PRELUDE
// ============================================================

/// Security prelude — all essential security types.
///
/// ```rust
/// use aevor_security::prelude::*;
/// ```
pub mod prelude {
    pub use crate::validation::{
        SecurityValidator, ValidationRule, SecurityCheck, ValidationResult,
        InfrastructureSecurityPolicy, ValidationContext,
    };
    pub use crate::threat_detection::{
        ThreatDetector, ThreatSignature, AnomalyScore, ThreatAlert,
        PrivacyPreservingDetector, InfrastructureThreat,
    };
    pub use crate::mitigation::{
        MitigationStrategy, AutomaticMitigation, MitigationResult,
        IsolationAction, ThrottleAction, BanAction,
    };
    pub use crate::cross_platform::{
        CrossPlatformVerifier, BehavioralConsistencyCheck, PlatformSecurityAudit,
        ConsistencyViolation, PlatformComplianceReport,
    };
    pub use crate::byzantine::{
        ByzantineAnalyzer, ExtendedByzantineEvidence, ByzantinePattern,
        CoordinatedAttackDetector, ByzantineReport,
    };
    pub use crate::auth::{
        ValidatorAuthenticator, AuthenticationChallenge, AuthenticationProof,
        TeeBackedIdentity, IdentityVerification,
    };
    pub use crate::network_security::{
        NetworkSecurityMonitor, DdosProtection, SybilResistance,
        EclipseAttackPrevention, NetworkSecurityStatus,
    };
    pub use crate::tee_integrity::{
        TeeIntegrityMonitor, EnclaveIntegrityProof, CompromiseIndicator,
        IntegrityViolationResponse, TeeHealthStatus,
    };
    pub use crate::audit::{
        SecurityAuditLog, AuditEntry, AuditQuery, ImmutableAuditTrail,
        AuditPrivacyLevel,
    };
    pub use crate::slashing::{
        SlashingCoordinator, SlashingEvidence, SlashingDecision,
        PenaltyCalculator, SlashingRecord,
    };
    pub use crate::{SecurityError, SecurityResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from security operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum SecurityError {
    /// Validator failed authentication.
    #[error("authentication failed for validator {validator_id}: {reason}")]
    AuthenticationFailed {
        /// Validator identifier.
        validator_id: String,
        /// Reason for failure.
        reason: String,
    },

    /// TEE integrity violation detected.
    #[error("TEE integrity violation on platform {platform}: {description}")]
    TeeIntegrityViolation {
        /// Platform where violation was detected.
        platform: String,
        /// Description of the violation.
        description: String,
    },

    /// Cross-platform behavioral inconsistency detected.
    #[error("cross-platform inconsistency: {description}")]
    CrossPlatformInconsistency {
        /// Description of the inconsistency.
        description: String,
    },

    /// Slashing evidence is insufficient or invalid.
    #[error("invalid slashing evidence: {reason}")]
    InvalidSlashingEvidence {
        /// Reason evidence is invalid.
        reason: String,
    },

    /// `DDoS` attack threshold exceeded.
    #[error("DDoS threshold exceeded: {attack_type}")]
    DdosThresholdExceeded {
        /// Type of `DDoS` attack detected.
        attack_type: String,
    },

    /// Security policy violation detected.
    #[error("security policy violation: {policy} — {description}")]
    PolicyViolation {
        /// Name of the violated policy.
        policy: String,
        /// Description of the violation.
        description: String,
    },

    /// Cryptographic signature verification failed.
    ///
    /// Raised when a validator's signature over an attestation, proposal, or
    /// vote cannot be verified against their registered public key.
    #[error("invalid signature: {reason}")]
    InvalidSignature {
        /// Reason for signature failure (e.g. "key mismatch", "malformed").
        reason: String,
    },
}

/// Convenience alias for security results.
pub type SecurityResult<T> = Result<T, SecurityError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum number of authentication failures before rate-limiting.
pub const MAX_AUTH_FAILURES_BEFORE_THROTTLE: u32 = 5;

/// Rate limit window for authentication attempts in seconds.
pub const AUTH_RATE_LIMIT_WINDOW_SECONDS: u64 = 60;

/// Minimum cross-platform consistency score (0.0–1.0).
pub const MIN_CROSS_PLATFORM_CONSISTENCY_SCORE: f64 = 0.999;

/// `DDoS` connection rate threshold (connections per second per IP).
pub const DDOS_CONNECTION_RATE_THRESHOLD: u64 = 100;

/// Maximum audit log entries before rotation.
pub const AUDIT_LOG_MAX_ENTRIES: usize = 1_000_000;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistency_score_threshold_is_near_perfect() {
        assert!(MIN_CROSS_PLATFORM_CONSISTENCY_SCORE > 0.99);
        assert!(MIN_CROSS_PLATFORM_CONSISTENCY_SCORE <= 1.0);
    }

    #[test]
    fn auth_rate_limit_values_are_reasonable() {
        assert!(MAX_AUTH_FAILURES_BEFORE_THROTTLE >= 3);
        assert!(AUTH_RATE_LIMIT_WINDOW_SECONDS >= 30);
    }


    #[test]
    fn security_error_formats() {
        let e = SecurityError::InvalidSignature { reason: "bad key".into() };
        assert!(e.to_string().contains("bad key"));

        let e2 = SecurityError::InvalidSlashingEvidence { reason: "missing proof".into() };
        assert!(e2.to_string().contains("missing proof"));
    }

    #[test]
    fn slashing_evidence_type_variants_exist() {
        use aevor_consensus::slashing::SlashingEvidenceType;
        let _ = SlashingEvidenceType::DoubleSign;
        let _ = SlashingEvidenceType::Liveness;
    }

    #[test]
    fn byzantine_report_coordinated_when_many_faults() {
        use byzantine::ByzantineAnalyzer;
        use aevor_core::consensus::{ByzantineFaultProof, ByzantineFaultType, ConsensusTimestamp};
        use aevor_core::primitives::Hash256;

        let make_fault = |n: u8| -> ByzantineFaultProof {
            ByzantineFaultProof {
                offender: Hash256([n; 32]),
                fault_type: ByzantineFaultType::Equivocation,
                evidence_a: vec![n],
                evidence_b: Some(vec![n + 1]),
                timestamp: ConsensusTimestamp::GENESIS,
            }
        };

        // 0 faults → not coordinated
        let report = ByzantineAnalyzer::analyze(&[]);
        assert!(!report.is_coordinated_attack);

        // 3+ faults from distinct validators → coordinated
        let faults = [make_fault(1), make_fault(2), make_fault(3)];
        let report3 = ByzantineAnalyzer::analyze(&faults);
        assert!(report3.is_coordinated_attack);
        assert_eq!(report3.affected_validators.len(), 3);
    }

    #[test]
    fn network_security_monitor_reports_status() {
        use network_security::NetworkSecurityMonitor;
        let monitor = NetworkSecurityMonitor::new(100, aevor_core::primitives::Amount::ZERO, 8);
        let status = monitor.status(100, 10);
        // Status should always return a valid value
        let _ = status;
    }
}
