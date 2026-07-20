//! # Cryptographic Abstraction Types
//!
//! Cross-system cryptographic types used as interchange formats throughout AEVOR.
//! These types abstract over specific cryptographic algorithms to enable
//! cross-platform consistency (SGX, SEV, TrustZone, Keystone, Nitro) without
//! hard-coding algorithm choices in infrastructure code.
//!
//! **No homomorphic encryption** — the 1000× overhead makes it incompatible
//! with AEVOR's 200,000+ TPS performance target. Privacy is achieved through
//! TEE isolation and ZK proofs.

use serde::{Deserialize, Serialize};
use crate::primitives::Hash256;

// ============================================================
// PROVING SYSTEM
// ============================================================

/// Identifies a zero-knowledge or cryptographic proving system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProvingSystem {
    /// Groth16 — smallest proof size, fast verification.
    Groth16,
    /// PLONK — universal setup, flexible circuits.
    Plonk,
    /// Halo2 — no trusted setup, recursive proofs.
    Halo2,
    /// STARK — post-quantum secure, large proofs.
    Stark,
    /// Bulletproofs — no trusted setup, good for range proofs.
    Bulletproofs,
}

impl ProvingSystem {
    /// Returns the canonical name of this proving system.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Groth16 => "Groth16",
            Self::Plonk => "PLONK",
            Self::Halo2 => "Halo2",
            Self::Stark => "STARK",
            Self::Bulletproofs => "Bulletproofs",
        }
    }

    /// Whether this system requires a trusted setup ceremony.
    pub fn requires_trusted_setup(&self) -> bool {
        matches!(self, Self::Groth16 | Self::Plonk)
    }

    /// Whether this system is post-quantum secure.
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::Stark)
    }

    /// Typical proof size in bytes for a moderately complex circuit.
    pub fn typical_proof_size_bytes(&self) -> usize {
        match self {
            Self::Groth16 => 192,
            Self::Plonk => 800,
            Self::Halo2 => 1_200,
            Self::Stark => 50_000,
            Self::Bulletproofs => 2_500,
        }
    }
}

impl std::fmt::Display for ProvingSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================
// CRYPTO PROOF TYPE
// ============================================================

/// Classification of a cryptographic proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoProofType {
    /// Zero-knowledge proof of computation correctness.
    ZeroKnowledge {
        /// The proving system that generated this proof.
        system: ProvingSystem,
    },
    /// TEE attestation proof.
    TeeAttestation,
    /// Cryptographic commitment opening.
    CommitmentOpening,
    /// Threshold signature proof.
    ThresholdSignature,
    /// Aggregate BLS signature proof.
    AggregateSignature,
}

// ============================================================
// CRYPTO PROOF
// ============================================================

/// A generic cryptographic proof, wrapping the proof bytes and type metadata.
///
/// Used as an interchange type when infrastructure code needs to pass proofs
/// across subsystem boundaries without knowing the specific proof system.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoProof {
    /// Classification of this proof.
    pub proof_type: CryptoProofType,
    /// Serialized proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Public inputs (committed values or statement being proven).
    pub public_inputs: Vec<Vec<u8>>,
    /// Hash of the circuit / statement this proof is for.
    pub circuit_hash: Hash256,
}

impl CryptoProof {
    /// Create a new crypto proof.
    pub fn new(
        proof_type: CryptoProofType,
        proof_bytes: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        circuit_hash: Hash256,
    ) -> Self {
        Self { proof_type, proof_bytes, public_inputs, circuit_hash }
    }

    /// Returns `true` if this is a zero-knowledge proof.
    pub fn is_zk_proof(&self) -> bool {
        matches!(self.proof_type, CryptoProofType::ZeroKnowledge { .. })
    }

    /// Returns `true` if this is a TEE attestation.
    pub fn is_tee_attestation(&self) -> bool {
        matches!(self.proof_type, CryptoProofType::TeeAttestation)
    }

    /// Returns the proof size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.proof_bytes.len()
    }
}

// ============================================================
// ZERO KNOWLEDGE PROOF
// ============================================================

/// A typed zero-knowledge proof from a specific proving system.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroKnowledgeProof {
    /// The proving system that generated this proof.
    pub system: ProvingSystem,
    /// Serialized proof bytes.
    pub proof: Vec<u8>,
    /// Public inputs — the statement being proven.
    pub public_inputs: Vec<Vec<u8>>,
    /// Verification key identifier (hash of the vkey used).
    pub vkey_hash: Hash256,
    /// Whether this proof is part of a recursive chain.
    pub is_recursive: bool,
}

impl ZeroKnowledgeProof {
    /// Convert to a generic `CryptoProof`.
    pub fn to_crypto_proof(&self) -> CryptoProof {
        CryptoProof {
            proof_type: CryptoProofType::ZeroKnowledge { system: self.system },
            proof_bytes: self.proof.clone(),
            public_inputs: self.public_inputs.clone(),
            circuit_hash: self.vkey_hash,
        }
    }

    /// Proof size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.proof.len()
    }
}

// ============================================================
// BLS SIGNATURE
// ============================================================

/// A single BLS12-381 signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsSignature {
    /// The signature bytes (BLS12-381 G1 or G2 point, compressed).
    pub bytes: Vec<u8>,
    /// The public key that produced this signature.
    pub signer_public_key: Vec<u8>,
}

impl BlsSignature {
    /// Create from raw signature bytes and a signer public key.
    pub fn new(bytes: Vec<u8>, signer_public_key: Vec<u8>) -> Self {
        Self { bytes, signer_public_key }
    }
}

// ============================================================
// AGGREGATE SIGNATURE
// ============================================================

/// An aggregated BLS12-381 signature from multiple signers.
///
/// Aggregation reduces n individual signatures to a single constant-size
/// signature, enabling efficient multi-validator finality proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateSignature {
    /// The aggregated signature bytes.
    pub aggregate: Vec<u8>,
    /// Number of signatures combined in this aggregate.
    pub signer_count: usize,
    /// Bitmap indicating which validators in a known set signed.
    pub participant_bitmap: Vec<u8>,
    /// Hash of the message all signers signed.
    pub message_hash: Hash256,
}

impl AggregateSignature {
    /// Returns `true` if this aggregate was produced by at least `n` signers.
    pub fn has_at_least_n_signers(&self, n: usize) -> bool {
        self.signer_count >= n
    }
}

// ============================================================
// COMMITMENT SCHEME
// ============================================================

/// Identifies the commitment scheme used for a commitment value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CommitmentScheme {
    /// Pedersen commitment (additively homomorphic, information-theoretically hiding).
    Pedersen,
    /// BLAKE3-based hash commitment (computationally binding, computationally hiding).
    Blake3Hash,
    /// KZG polynomial commitment (efficient opening proofs).
    Kzg,
}

/// An opaque commitment to a value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentProof {
    /// The commitment scheme used.
    pub scheme: CommitmentScheme,
    /// The commitment value (scheme-specific encoding).
    pub commitment: Vec<u8>,
    /// Zero-knowledge proof that the commitment is well-formed.
    pub wellformedness_proof: Option<Vec<u8>>,
}

/// An opening of a commitment — reveals the committed value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentOpening {
    /// The commitment being opened.
    pub commitment: CommitmentProof,
    /// The revealed value.
    pub value: Vec<u8>,
    /// Randomness used to create the commitment.
    pub randomness: [u8; 32],
    /// Proof that this opening is consistent with the commitment.
    pub opening_proof: Vec<u8>,
}

// ============================================================
// CROSS PLATFORM ATTESTATION
// ============================================================

/// An attestation that is valid across multiple TEE platforms simultaneously.
///
/// For the `PoU` consensus mechanism, attestations from validators on different
/// TEE hardware must be verifiable by all other validators regardless of their
/// own TEE platform. `CrossPlatformAttestation` wraps all platform-specific
/// attestation formats and provides a unified verification interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossPlatformAttestation {
    /// The primary attestation (from the validator's TEE).
    pub primary: crate::tee::AttestationReport,
    /// Secondary attestations from other TEE platforms if available.
    pub secondary: Vec<crate::tee::AttestationReport>,
    /// Cross-platform consistency proof.
    pub consistency_proof: Hash256,
    /// The computation hash all platforms agree on.
    pub agreed_computation_hash: Hash256,
}

impl CrossPlatformAttestation {
    /// Returns `true` if all secondary attestations agree on the computation hash.
    pub fn is_consistent(&self) -> bool {
        let primary_measurement = &self.primary.code_measurement;
        self.secondary
            .iter()
            .all(|s| &s.code_measurement == primary_measurement)
    }
}

// ============================================================
// SECURITY CLAIMS
// ============================================================

/// Security properties claimed by a cryptographic construction.
///
/// Enables infrastructure code to reason about security properties without
/// knowing the specific cryptographic algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityClaims {
    /// Security level in bits (e.g., 128, 256).
    pub security_bits: u32,
    /// Whether this construction is post-quantum secure.
    pub post_quantum: bool,
    /// Whether the construction has a trusted setup requirement.
    pub requires_trusted_setup: bool,
    /// Whether a security audit has been performed.
    pub audited: bool,
    /// The specific hardness assumptions relied on.
    pub hardness_assumptions: Vec<String>,
}

impl SecurityClaims {
    /// Minimum production-grade security claims (128-bit, classical security).
    pub fn minimum_production() -> Self {
        Self {
            security_bits: 128,
            post_quantum: false,
            requires_trusted_setup: false,
            audited: true,
            hardness_assumptions: vec!["DLOG".into(), "CDH".into()],
        }
    }

    /// Returns `true` if this satisfies minimum production security requirements.
    pub fn meets_minimum_production(&self) -> bool {
        self.security_bits >= 128 && self.audited
    }
}

// ============================================================
// CRYPTO AGILITY: scheme-tagged signature / public-key envelope
// ============================================================

/// Identifier for a signature scheme, carried on the wire so a verifier knows
/// how to interpret the bytes.
///
/// This is the agility discriminant. It is **additive**: introducing a new
/// scheme (post-quantum or otherwise) means adding a variant here plus one
/// verification arm in `aevor-crypto` — nothing that stores a signature
/// changes. Classical and post-quantum schemes coexist under one type, so
/// switching between them (or between two post-quantum schemes) is a data
/// change, not a code migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum SignatureSchemeId {
    // ── Classical (implemented) ──────────────────────────────
    /// Ed25519 — fast, small; default transaction signing.
    Ed25519 = 0x0001,
    /// BLS12-381 — aggregatable; consensus/finality.
    Bls12_381 = 0x0002,

    // ── Post-quantum, lattice (NIST FIPS 204 / draft FN-DSA) ──
    /// ML-DSA-44 (Dilithium2).
    MlDsa44 = 0x0101,
    /// ML-DSA-65 (Dilithium3).
    MlDsa65 = 0x0102,
    /// ML-DSA-87 (Dilithium5).
    MlDsa87 = 0x0103,
    /// FN-DSA-512 (Falcon-512) — smaller signatures than ML-DSA.
    FnDsa512 = 0x0111,

    // ── Post-quantum, hash-based (NIST FIPS 205) ─────────────
    /// SLH-DSA-128s (SPHINCS+-128s) — conservative, for root-of-trust.
    SlhDsa128s = 0x0201,

    // ── Post-quantum, symmetric / MPC-in-the-Head (candidate) ─
    /// FAEST-128s — `AES`-based `MPCitH` (NIST additional-signature candidate).
    Faest128s = 0x0301,

    // ── Hybrids (classical bytes ‖ post-quantum bytes) ───────
    /// Ed25519 ‖ ML-DSA-65 — classical + post-quantum defence in depth.
    HybridEd25519MlDsa65 = 0x1001,
}

impl SignatureSchemeId {
    /// Whether this scheme provides post-quantum security (fully or in hybrid).
    #[must_use]
    pub fn is_post_quantum(self) -> bool {
        !matches!(self, SignatureSchemeId::Ed25519 | SignatureSchemeId::Bls12_381)
    }

    /// Whether this scheme aggregates (only BLS today).
    #[must_use]
    pub fn is_aggregatable(self) -> bool {
        matches!(self, SignatureSchemeId::Bls12_381)
    }

    /// Human-readable name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SignatureSchemeId::Ed25519 => "Ed25519",
            SignatureSchemeId::Bls12_381 => "BLS12-381",
            SignatureSchemeId::MlDsa44 => "ML-DSA-44",
            SignatureSchemeId::MlDsa65 => "ML-DSA-65",
            SignatureSchemeId::MlDsa87 => "ML-DSA-87",
            SignatureSchemeId::FnDsa512 => "FN-DSA-512",
            SignatureSchemeId::SlhDsa128s => "SLH-DSA-128s",
            SignatureSchemeId::Faest128s => "FAEST-128s",
            SignatureSchemeId::HybridEd25519MlDsa65 => "Hybrid(Ed25519+ML-DSA-65)",
        }
    }
}

/// A variable-length, scheme-tagged signature envelope.
///
/// The single wire type for all signatures regardless of algorithm. A verifier
/// reads `scheme` and dispatches to the right algorithm over `bytes`. This is
/// what makes non-PQ↔PQ and PQ↔PQ switching seamless: the envelope never
/// changes, only the tag and payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiSignature {
    /// Which scheme produced `bytes`.
    pub scheme: SignatureSchemeId,
    /// The scheme-specific signature bytes.
    pub bytes: Vec<u8>,
}

impl MultiSignature {
    /// Construct a scheme-tagged signature.
    #[must_use]
    pub fn new(scheme: SignatureSchemeId, bytes: Vec<u8>) -> Self {
        Self { scheme, bytes }
    }

    /// Signature length in bytes (useful for wire-size accounting).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the signature payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Whether this signature is post-quantum (by scheme).
    #[must_use]
    pub fn is_post_quantum(&self) -> bool {
        self.scheme.is_post_quantum()
    }
}

/// A variable-length, scheme-tagged public key envelope.
///
/// Post-quantum public keys are far larger and variable-sized, so keys use the
/// same tagged-envelope pattern as signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiPublicKey {
    /// Which scheme this key belongs to.
    pub scheme: SignatureSchemeId,
    /// The scheme-specific public-key bytes.
    pub bytes: Vec<u8>,
}

impl MultiPublicKey {
    /// Construct a scheme-tagged public key.
    #[must_use]
    pub fn new(scheme: SignatureSchemeId, bytes: Vec<u8>) -> Self {
        Self { scheme, bytes }
    }

    /// Public-key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the key payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groth16_has_smallest_proof_size() {
        assert!(
            ProvingSystem::Groth16.typical_proof_size_bytes()
                < ProvingSystem::Plonk.typical_proof_size_bytes()
        );
    }

    #[test]
    fn stark_is_post_quantum() {
        assert!(ProvingSystem::Stark.is_post_quantum());
        assert!(!ProvingSystem::Groth16.is_post_quantum());
    }

    #[test]
    fn groth16_requires_trusted_setup() {
        assert!(ProvingSystem::Groth16.requires_trusted_setup());
        assert!(!ProvingSystem::Halo2.requires_trusted_setup());
    }

    #[test]
    fn crypto_proof_zk_detection() {
        let proof = CryptoProof::new(
            CryptoProofType::ZeroKnowledge { system: ProvingSystem::Groth16 },
            vec![1, 2, 3],
            vec![],
            Hash256::ZERO,
        );
        assert!(proof.is_zk_proof());
        assert!(!proof.is_tee_attestation());
    }

    #[test]
    fn cross_platform_consistency_with_matching_measurements() {
        let measurement = Hash256([1u8; 32]);
        let primary = crate::tee::AttestationReport {
            platform: crate::tee::TeePlatform::IntelSgx,
            raw_report: vec![],
            code_measurement: measurement,
            signer_measurement: Hash256::ZERO,
            nonce: [0u8; 32],
            is_production: true,
            svn: 1,
            user_data: vec![],
        };
        let secondary = crate::tee::AttestationReport {
            platform: crate::tee::TeePlatform::AmdSev,
            raw_report: vec![],
            code_measurement: measurement, // same
            signer_measurement: Hash256::ZERO,
            nonce: [0u8; 32],
            is_production: true,
            svn: 1,
            user_data: vec![],
        };
        let cross_attest = CrossPlatformAttestation {
            primary,
            secondary: vec![secondary],
            consistency_proof: Hash256::ZERO,
            agreed_computation_hash: measurement,
        };
        assert!(cross_attest.is_consistent());
    }

    #[test]
    fn security_claims_minimum_production() {
        let claims = SecurityClaims::minimum_production();
        assert!(claims.meets_minimum_production());
        assert_eq!(claims.security_bits, 128);
    }

    #[test]
    fn aggregate_signature_signer_count() {
        let agg = AggregateSignature {
            aggregate: vec![0u8; 48],
            signer_count: 5,
            participant_bitmap: vec![0xFF],
            message_hash: Hash256::ZERO,
        };
        assert!(agg.has_at_least_n_signers(5));
        assert!(!agg.has_at_least_n_signers(6));
    }
}
