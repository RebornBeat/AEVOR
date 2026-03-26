//! # AEVOR ZK: Zero-Knowledge with Multi-Party Computation
//!
//! `aevor-zk` provides zero-knowledge proof generation, verification, and multi-party
//! secure computation capabilities integrated with AEVOR's TEE infrastructure.
//!
//! ## Design Philosophy
//!
//! ZK proofs in AEVOR serve a specific purpose: enabling **public verification of private
//! computation results** without revealing computation inputs. This is complementary to
//! TEE-based privacy (which provides hardware-backed confidentiality) rather than a
//! replacement for it.
//!
//! The combination provides capabilities neither approach achieves alone:
//! - TEE provides efficient confidential computation (1.1–1.3× overhead)
//! - ZK provides mathematical proofs that the TEE computed correctly
//! - Together: verifiable confidential computation with practical performance
//!
//! ## Proving Systems
//!
//! | System | Proof Size | Verify Time | Setup | Best For |
//! |--------|-----------|-------------|-------|----------|
//! | Groth16 | 200 bytes | <1ms | Trusted | Small circuits, high throughput |
//! | PLONK | 2–5 KB | 5–10ms | Universal | Medium circuits |
//! | Halo2 | 3–8 KB | 10–20ms | None | Recursive proofs |
//! | STARK | 50–500 KB | 50–200ms | None | Large circuits, transparency |
//! | Bulletproofs | 1–10 KB | 5–50ms | None | Range proofs |
//!
//! ## Multi-Party Computation
//!
//! The MPC module provides secure computation protocols where multiple parties
//! contribute inputs without revealing individual contributions. TEE coordination
//! provides hardware-backed security for MPC protocols, dramatically improving
//! performance over software-only MPC approaches.
//!
//! ## Privacy Overhead
//!
//! ZK proof generation adds 2–5× overhead compared to unverified computation.
//! For operations where this is acceptable, ZK provides the strongest possible
//! privacy guarantees (information-theoretic, not computational).

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Proof generation: circuit compilation and witness generation.
pub mod proving;

/// Proof verification: efficient batch and single proof verification.
pub mod verification;

/// Circuit library: common ZK circuits (range proofs, Merkle paths, etc.).
pub mod circuits;

/// Groth16 proving system integration.
pub mod groth16;

/// PLONK proving system integration.
pub mod plonk;

/// Halo2 proving system integration with recursive proof support.
pub mod halo2;

/// STARK proving system integration (transparent, no trusted setup).
pub mod stark;

/// Bulletproofs for range proofs and inner product arguments.
pub mod bulletproofs;

/// Multi-party computation: secure computation with TEE coordination.
pub mod mpc;

/// Commitment schemes used in ZK proofs.
pub mod commitments;

/// Trusted setup coordination: ceremony management for Groth16/PLONK.
pub mod trusted_setup;

/// TEE-ZK integration: hardware-accelerated proof generation and verification.
pub mod tee_integration;

/// Recursive proofs: proof composition and aggregation.
pub mod recursive;

// ============================================================
// PRELUDE
// ============================================================

/// ZK prelude — all essential zero-knowledge types.
///
/// ```rust
/// use aevor_zk::prelude::*;
/// ```
pub mod prelude {
    pub use crate::proving::{
        ProofRequest, ProofGenerator, Witness, Circuit,
        ProofGenerationResult, CircuitStats,
    };
    pub use aevor_crypto::proofs::ProvingKey;
    pub use crate::verification::{
        ProofVerifier, VerifyingKey, BatchVerifier, VerificationResult,
        PublicInputs, VerificationContext,
    };
    pub use crate::circuits::{
        RangeProofCircuit, MerklePathCircuit, SignatureCircuit,
        BalanceCircuit, PrivacyPreservingCircuit,
    };
    pub use crate::groth16::{
        Groth16Proof, Groth16Prover, Groth16Verifier, Groth16ProvingKey,
        Groth16VerifyingKey,
    };
    pub use crate::plonk::{
        PlonkProver, PlonkVerifier, PlonkProvingKey,
        PlonkVerifyingKey, UniversalSrs,
    };
    pub use aevor_crypto::proofs::PlonkProof;
    pub use crate::halo2::{
        Halo2Proof, Halo2Prover, Halo2Verifier, RecursiveProof,
    };
    pub use crate::bulletproofs::{
        BulletproofProof, RangeProof, InnerProductProof,
        BulletproofVerifier,
    };
    pub use crate::mpc::{
        MpcCoordinator, MpcParty, MpcInput, MpcOutput, MpcProtocol,
        SecureAggregation, PrivacyPreservingMpc, TeeEnhancedMpc,
    };
    pub use crate::recursive::{
        RecursiveProver, ProofComposition, AggregatedProof,
        ProofAccumulator, RecursiveVerifier,
    };
    pub use crate::tee_integration::{
        TeeAcceleratedProver, TeeProofVerifier, AttestationBoundProof,
        TeeWitnessGenerator,
    };
    pub use crate::{ZkError, ZkResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from zero-knowledge proof operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ZkError {
    /// Proof generation failed.
    #[error("proof generation failed: {reason}")]
    ProofGenerationFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Proof verification failed — the proof is invalid.
    #[error("proof verification failed")]
    ProofVerificationFailed,

    /// Circuit compilation error.
    #[error("circuit compilation error: {0}")]
    CircuitError(String),

    /// Witness generation failed.
    #[error("witness generation failed: {reason}")]
    WitnessError {
        /// Reason for failure.
        reason: String,
    },

    /// Trusted setup not available for the requested proving system.
    #[error("trusted setup not available for {proving_system}")]
    TrustedSetupUnavailable {
        /// Name of the proving system.
        proving_system: String,
    },

    /// MPC protocol failed.
    #[error("MPC protocol failed: {reason}")]
    MpcFailed {
        /// Reason for MPC failure.
        reason: String,
    },

    /// Recursive proof composition failed.
    #[error("recursive proof composition failed: {reason}")]
    RecursiveFailed {
        /// Reason for failure.
        reason: String,
    },
}

/// Convenience alias for ZK results.
pub type ZkResult<T> = Result<T, ZkError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum circuit size (number of gates) for practical proving times.
pub const MAX_CIRCUIT_GATES: usize = 1_000_000;

/// Groth16 proof size in bytes.
pub const GROTH16_PROOF_SIZE: usize = 192;

/// PLONK proof size in bytes (approximate, circuit-dependent).
pub const PLONK_PROOF_SIZE_APPROX: usize = 2_048;

/// Minimum batch size for batch proof verification efficiency gains.
pub const MIN_BATCH_VERIFY_SIZE: usize = 8;

/// Maximum number of MPC parties.
pub const MAX_MPC_PARTIES: usize = 256;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_size_constants_are_positive() {
        assert!(GROTH16_PROOF_SIZE > 0);
        assert!(PLONK_PROOF_SIZE_APPROX > GROTH16_PROOF_SIZE);
    }

    #[test]
    fn circuit_gate_limit_is_practical() {
        assert!(MAX_CIRCUIT_GATES >= 10_000);
        assert!(MAX_CIRCUIT_GATES <= 100_000_000);
    }
}
