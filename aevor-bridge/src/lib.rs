//! # AEVOR Bridge: Cross-Chain Privacy-Preserving Interoperability
//!
//! `aevor-bridge` implements AEVOR's cross-chain bridge architecture, enabling
//! privacy-preserving interoperability with external blockchain networks while
//! maintaining AEVOR's mathematical security guarantees throughout cross-chain operations.
//!
//! ## Bridge Architecture Principles
//!
//! **TEE-Secured Operations**: All cross-chain operations execute within TEE environments,
//! providing hardware-backed security that exceeds traditional multi-sig bridge approaches
//! or economic assumption-based bridges.
//!
//! **Privacy Preservation Across Chains**: Cross-chain operations maintain privacy boundaries.
//! Information disclosed to external chains is controlled through the same selective
//! disclosure mechanisms used within AEVOR.
//!
//! **Mathematical Verification**: Cross-chain state proofs use cryptographic verification
//! (Merkle proofs, ZK proofs) rather than optimistic assumptions requiring challenge periods.
//!
//! **No Protocol Overreach**: This crate provides communication and verification primitives
//! for cross-chain coordination. Application-specific bridge protocols (asset wrapping,
//! cross-chain DeFi, etc.) belong in application crates.
//!
//! ## Supported External Networks
//!
//! The bridge architecture is network-agnostic — any blockchain with a verifiable state
//! root can be bridged. Built-in integrations include Ethereum (EVM), Bitcoin (UTXO),
//! and other Move-based chains.
//!
//! ## Security Model
//!
//! Bridge security derives from:
//! 1. TEE attestation of cross-chain state observations
//! 2. Multi-validator consensus on cross-chain event validity
//! 3. Cryptographic state proofs from external chains
//! 4. ZK proofs of asset existence and ownership

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Bridge core: message passing, state commitment, finality tracking.
pub mod bridge;

/// State verification: Merkle proofs, ZK proofs, attestation for external chains.
pub mod verification;

/// Asset standards: normalized asset representation across chain types.
pub mod assets;

/// EVM protocol: Ethereum and EVM-compatible chain integration.
pub mod evm;

/// Bitcoin/UTXO protocol: Bitcoin and UTXO-model chain integration.
pub mod utxo;

/// Move chain protocol: cross-chain coordination with other Move blockchains.
pub mod move_chain;

/// Privacy layer: selective disclosure for cross-chain operations.
pub mod privacy;

/// Relayer coordination: validator-based cross-chain message relaying.
pub mod relayer;

/// Message queue: cross-chain message ordering and deduplication.
pub mod message_queue;

/// Bridge metrics: cross-chain volume, latency, security status.
pub mod metrics;

// ============================================================
// PRELUDE
// ============================================================

/// Bridge prelude — all essential bridge types.
///
/// ```rust
/// use aevor_bridge::prelude::*;
/// ```
pub mod prelude {
    pub use crate::bridge::{
        Bridge, BridgeConfig, CrossChainMessage, BridgeHandle,
        ChainConnection, BridgeState,
    };
    pub use crate::verification::{
        CrossChainVerifier, ExternalStateProof, MerkleVerification,
        ZkCrossChainProof, AttestationVerification, FinalityProof,
    };
    pub use crate::assets::{
        CrossChainAsset, AssetStandard, WrappedAsset, NativeAsset,
        AssetLock, AssetMint, AssetBurn,
    };
    pub use crate::evm::{
        EvmBridge, EvmChainConfig, EthereumStateProof, EvmEvent,
        EvmTransaction, SolidityInterop,
    };
    pub use crate::utxo::{
        UtxoBridge, BitcoinChainConfig, UtxoStateProof, BitcoinSpv,
        UtxoTransaction,
    };
    pub use crate::privacy::{
        CrossChainPrivacy, SelectiveCrossChainDisclosure,
        PrivacyPreservingBridge, CrossChainPrivacyProof,
    };
    pub use crate::relayer::{
        RelayerSet, RelayerEntry, RelayMessage, RelayConfirmation,
        ValidatorRelayer, RelayerConsensus,
    };
    pub use crate::message_queue::{
        CrossChainQueue, QueuedMessage, MessageDeduplication,
        OrderedDelivery, QueueStatus,
    };
    pub use crate::{BridgeError, BridgeResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from bridge operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum BridgeError {
    /// External chain proof verification failed.
    #[error("external chain proof invalid for chain {chain_id}: {reason}")]
    InvalidExternalProof {
        /// Chain identifier.
        chain_id: String,
        /// Reason proof is invalid.
        reason: String,
    },

    /// Cross-chain finality not yet achieved.
    #[error("finality not achieved for message {message_id}: {confirmations}/{required} confirmations")]
    FinalityNotAchieved {
        /// Message identifier.
        message_id: String,
        /// Confirmations received.
        confirmations: u64,
        /// Confirmations required.
        required: u64,
    },

    /// Asset lock or mint operation failed.
    #[error("asset operation failed: {operation} — {reason}")]
    AssetOperationFailed {
        /// Operation name (lock, mint, burn).
        operation: String,
        /// Reason for failure.
        reason: String,
    },

    /// Chain connection lost or unavailable.
    #[error("chain {chain_id} connection unavailable: {reason}")]
    ChainUnavailable {
        /// Chain identifier.
        chain_id: String,
        /// Reason for unavailability.
        reason: String,
    },

    /// Cross-chain privacy disclosure violated policy.
    #[error("cross-chain privacy violation: {description}")]
    PrivacyViolation {
        /// Description of the violation.
        description: String,
    },

    /// Duplicate message detected.
    #[error("duplicate cross-chain message: {message_id}")]
    DuplicateMessage {
        /// Duplicate message identifier.
        message_id: String,
    },
}

/// Convenience alias for bridge results.
pub type BridgeResult<T> = Result<T, BridgeError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Minimum confirmations required on Ethereum before AEVOR accepts finality.
pub const ETH_FINALITY_CONFIRMATIONS: u64 = 12;

/// Minimum confirmations on Bitcoin before AEVOR accepts UTXO finality.
pub const BTC_FINALITY_CONFIRMATIONS: u64 = 6;

/// Maximum cross-chain message size in bytes (256 KiB).
pub const MAX_CROSS_CHAIN_MESSAGE_SIZE: usize = 262_144;

/// Maximum age of a cross-chain message before it expires (24 hours in seconds).
pub const MAX_MESSAGE_AGE_SECONDS: u64 = 86_400;

/// Maximum number of relayers in the relayer set.
pub const MAX_RELAYER_SET_SIZE: usize = 64;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finality_confirmations_are_positive() {
        assert!(ETH_FINALITY_CONFIRMATIONS > 0);
        assert!(BTC_FINALITY_CONFIRMATIONS > 0);
    }

    #[test]
    fn message_limits_are_reasonable() {
        assert!(MAX_CROSS_CHAIN_MESSAGE_SIZE > 0);
        assert!(MAX_MESSAGE_AGE_SECONDS >= 3600); // At least 1 hour
    }
}
