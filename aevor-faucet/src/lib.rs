//! # AEVOR Faucet: Decentralized Resource Distribution
//!
//! `aevor-faucet` provides decentralized testnet and devnet token distribution
//! through validator-coordinated rate limiting, without identity verification
//! systems that would compromise privacy or create centralized dependencies.
//!
//! ## Decentralized Design
//!
//! Traditional faucets rely on centralized rate limiting servers or identity
//! verification (GitHub OAuth, phone verification, etc.) that create:
//! - Single points of failure
//! - Privacy-compromising identity requirements
//! - Centralized control over who can access testnet resources
//!
//! AEVOR's faucet uses **validator-coordinated rate limiting** through blockchain
//! consensus mechanisms, providing:
//! - Decentralized rate enforcement without central servers
//! - Privacy-preserving access without identity requirements
//! - Sybil resistance through cryptographic proof-of-work challenges
//! - Fair distribution verified by multiple validators
//!
//! ## Rate Limiting Mechanisms
//!
//! Rate limiting uses a combination of:
//! 1. **Address-based cooldowns**: Addresses must wait between requests
//! 2. **Proof-of-work challenges**: Light computational work prevents bot flooding
//! 3. **Validator consensus**: Rate records are stored in blockchain state
//! 4. **Stake-weighted fairness**: Validators collectively enforce limits
//!
//! ## No Identity Verification
//!
//! This crate never requires phone numbers, email addresses, OAuth logins, or
//! any external identity verification. Sybil resistance comes from cryptographic
//! mechanisms and blockchain consensus, not surveillance.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Faucet core: request processing and distribution coordination.
pub mod faucet;

/// Rate limiting: decentralized rate enforcement through validator consensus.
pub mod rate_limiting;

/// Proof of work: light computational challenges for bot resistance.
pub mod pow;

/// Distribution records: blockchain-anchored distribution history.
pub mod records;

/// Cooldown management: per-address cooldown tracking.
pub mod cooldown;

/// Validator coordination: multi-validator consensus for rate records.
pub mod validator_coordination;

/// HTTP interface: faucet web API without identity requirements.
pub mod http;

/// Faucet metrics: distribution rates, request volumes, fairness metrics.
pub mod metrics;

// ============================================================
// PRELUDE
// ============================================================

/// Faucet prelude — all essential faucet types.
///
/// ```rust
/// use aevor_faucet::prelude::*;
/// ```
pub mod prelude {
    pub use crate::faucet::{
        Faucet, FaucetConfig, DistributionRequest, DistributionResult,
        FaucetBalance, FaucetStatus,
    };
    pub use crate::rate_limiting::{
        RateLimitRecord, RateLimitCheck, RateLimitState, ValidatorRateConsensus,
        RateLimitResult,
    };
    pub use crate::pow::{
        PowChallenge, PowSolution, PowDifficulty, PowVerifier,
        ChallengeGenerator,
    };
    pub use crate::records::{
        DistributionRecord, DistributionHistory, AddressRecord,
        RecordQuery, RecordVerification,
    };
    pub use crate::cooldown::{
        CooldownEntry, CooldownStatus, CooldownTracker, AddressCooldown,
    };
    pub use crate::http::{
        FaucetServer, RequestHandler, FaucetResponse, FaucetRequest,
        HttpConfig,
    };
    pub use crate::{FaucetError, FaucetResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from faucet operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum FaucetError {
    /// Address is in cooldown period and cannot receive tokens yet.
    #[error("address {address} in cooldown: {remaining_seconds}s remaining")]
    AddressInCooldown {
        /// Address in cooldown.
        address: String,
        /// Seconds remaining in cooldown.
        remaining_seconds: u64,
    },

    /// Proof of work solution is invalid or insufficient.
    #[error("invalid proof of work: {reason}")]
    InvalidProofOfWork {
        /// Reason the `PoW` is invalid.
        reason: String,
    },

    /// Faucet balance is insufficient to fulfill the request.
    #[error("insufficient faucet balance: {available} < {requested}")]
    InsufficientBalance {
        /// Available balance.
        available: u64,
        /// Requested amount.
        requested: u64,
    },

    /// Validator consensus could not be reached for rate limit record.
    #[error("validator consensus failed for rate record: {reason}")]
    ConsensusFailure {
        /// Reason consensus failed.
        reason: String,
    },

    /// Network type does not support faucet (mainnet).
    #[error("faucet not available on network: {network}")]
    NetworkNotSupported {
        /// Network where faucet is not available.
        network: String,
    },
}

/// Convenience alias for faucet results.
pub type FaucetResult<T> = Result<T, FaucetError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Default token distribution amount per request (1,000 test tokens).
pub const DEFAULT_DISTRIBUTION_AMOUNT: u64 = 1_000_000_000; // 1,000 AEVOR in nanoAEVOR

/// Default cooldown period between faucet requests in seconds (24 hours).
pub const DEFAULT_COOLDOWN_SECONDS: u64 = 86_400;

/// Default proof-of-work difficulty (leading zero bits in hash).
pub const DEFAULT_POW_DIFFICULTY: u32 = 16;

/// Maximum `PoW` solution attempts before challenge expires.
pub const MAX_POW_ATTEMPTS: u64 = 1_000_000;

/// `PoW` challenge expiry in seconds.
pub const POW_CHALLENGE_EXPIRY_SECONDS: u64 = 300;

/// Number of validators required to confirm a rate limit record.
pub const RATE_LIMIT_VALIDATOR_QUORUM: usize = 3;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_is_reasonable() {
        // 24 hours is reasonable — prevents abuse without excessive restriction
        assert_eq!(DEFAULT_COOLDOWN_SECONDS, 86_400);
    }

    #[test]
    fn pow_difficulty_is_feasible() {
        // 16 bits ~ 65,536 expected hashes — lightweight but sufficient
        assert!(DEFAULT_POW_DIFFICULTY >= 8);
        assert!(DEFAULT_POW_DIFFICULTY <= 24);
    }

    #[test]
    fn quorum_requires_multiple_validators() {
        assert!(RATE_LIMIT_VALIDATOR_QUORUM >= 2);
    }
}
