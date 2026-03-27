//! # Privacy Architecture Types
//!
//! Object-level privacy policies, selective disclosure, cross-privacy coordination,
//! and TEE-backed confidentiality types for AEVOR's mixed privacy architecture.
//!
//! AEVOR enables granular privacy control at the individual object level — each
//! object declares its own privacy policy independently of all other objects in
//! the same transaction or application context.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::primitives::Address;

// ============================================================
// PRIVACY LEVEL
// ============================================================

/// The privacy level of a blockchain object or execution context.
///
/// Privacy levels form a hierarchy: `Public < Protected < Private < Confidential`.
/// Higher levels provide stronger confidentiality but require more infrastructure
/// resources (TEE execution, ZK proofs) and may have higher gas costs.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
    Serialize, Deserialize, Default,
)]
#[repr(u8)]
pub enum PrivacyLevel {
    /// Full transparency — anyone can read and verify the object.
    ///
    /// Used for: public tokens, on-chain governance records, compliance data.
    /// TEE required: No.
    #[default]
    Public = 0,

    /// Selective transparency — specific fields can be disclosed to authorized parties.
    ///
    /// Used for: KYC data, regulatory compliance, business-partner data sharing.
    /// TEE required: No (for basic operations), Yes (for confidential disclosure).
    Protected = 1,

    /// Confidential by default — only the owner and explicitly authorized addresses can read.
    ///
    /// Used for: financial position data, personal records, proprietary algorithms.
    /// TEE required: Yes.
    Private = 2,

    /// Maximum confidentiality — hardware-isolated execution with metadata shielding.
    ///
    /// Used for: highly sensitive computations, anti-surveillance protection.
    /// TEE required: Yes (with anti-snooping protection).
    Confidential = 3,
}

impl PrivacyLevel {
    /// Returns `true` if TEE execution is required for this privacy level.
    pub fn requires_tee(&self) -> bool {
        matches!(self, Self::Private | Self::Confidential)
    }

    /// Returns `true` if anti-snooping protection is required.
    pub fn requires_anti_snooping(&self) -> bool {
        matches!(self, Self::Confidential)
    }

    /// Returns `true` if this level is at least as private as `other`.
    pub fn at_least(&self, other: Self) -> bool {
        (*self as u8) >= (other as u8)
    }

    /// Returns the more restrictive of two privacy levels.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        if (self as u8) >= (other as u8) { self } else { other }
    }

    /// Gas multiplier for this privacy level relative to public.
    pub fn gas_multiplier(&self) -> u64 {
        match self {
            Self::Public => 1,
            Self::Protected => 2,
            Self::Private => 4,
            Self::Confidential => 8,
        }
    }
}

impl std::fmt::Display for PrivacyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::Protected => write!(f, "Protected"),
            Self::Private => write!(f, "Private"),
            Self::Confidential => write!(f, "Confidential"),
        }
    }
}

// ============================================================
// CONFIDENTIALITY LEVEL
// ============================================================

/// Fine-grained confidentiality specification within a privacy context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfidentialityLevel {
    /// No confidentiality — fully transparent.
    None,
    /// Field-level confidentiality — specific fields are hidden.
    FieldLevel,
    /// Object-level confidentiality — entire object is encrypted.
    ObjectLevel,
    /// Computation-level confidentiality — inputs and outputs hidden.
    ComputationLevel,
    /// Maximum — computation, inputs, outputs, and metadata all hidden.
    Maximum,
}

// ============================================================
// PRIVACY POLICY
// ============================================================

/// The complete privacy policy for a single blockchain object.
///
/// Privacy policies are declared at object creation time and are immutable
/// by default (changes require a governance proposal or explicit owner action).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPolicy {
    /// Privacy level governing access to this object.
    pub level: PrivacyLevel,

    /// Access control policy defining who can read this object.
    pub read_policy: AccessPolicy,

    /// Access control policy defining who can write this object.
    pub write_policy: AccessPolicy,

    /// Selective disclosure configuration for this object.
    pub disclosure: SelectiveDisclosure,

    /// Whether this object can interact across privacy boundaries.
    pub cross_privacy_allowed: bool,

    /// TEE platform requirements for executing operations on this object.
    pub tee_requirements: Option<TeeRequirement>,
}

impl PrivacyPolicy {
    /// Create a fully public policy with open read/write access.
    pub fn public() -> Self {
        Self {
            level: PrivacyLevel::Public,
            read_policy: AccessPolicy::Public,
            write_policy: AccessPolicy::Owner,
            disclosure: SelectiveDisclosure::default(),
            cross_privacy_allowed: true,
            tee_requirements: None,
        }
    }

    /// Create a private policy with owner-only access.
    pub fn private(owner: Address) -> Self {
        Self {
            level: PrivacyLevel::Private,
            read_policy: AccessPolicy::Explicit {
                allowed: vec![owner],
            },
            write_policy: AccessPolicy::Owner,
            disclosure: SelectiveDisclosure::none(),
            cross_privacy_allowed: false,
            tee_requirements: Some(TeeRequirement::AnyPlatform),
        }
    }

    /// Create a confidential policy requiring TEE and anti-snooping.
    pub fn confidential(owner: Address) -> Self {
        Self {
            level: PrivacyLevel::Confidential,
            read_policy: AccessPolicy::Explicit {
                allowed: vec![owner],
            },
            write_policy: AccessPolicy::Owner,
            disclosure: SelectiveDisclosure::none(),
            cross_privacy_allowed: false,
            tee_requirements: Some(TeeRequirement::WithAntiSnooping),
        }
    }

    /// Check if `address` has read access under this policy.
    pub fn has_read_access(&self, address: &Address) -> bool {
        self.read_policy.allows(address)
    }

    /// Check if `address` has write access under this policy.
    pub fn has_write_access(&self, address: &Address) -> bool {
        self.write_policy.allows(address)
    }
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        Self::public()
    }
}

// ============================================================
// ACCESS POLICY
// ============================================================

/// Specifies who is permitted to access an object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessPolicy {
    /// Anyone can access (public objects).
    Public,

    /// Only the object owner can access.
    Owner,

    /// An explicit list of permitted addresses.
    Explicit {
        /// List of addresses permitted to access.
        allowed: Vec<Address>,
    },

    /// Access is gated on a cryptographic proof (e.g., membership proof).
    ProofGated {
        /// Identifier of the proof circuit or scheme.
        proof_scheme: String,
    },
}

impl AccessPolicy {
    /// Check if `address` is permitted under this policy.
    ///
    /// Note: `Owner` requires knowing the object's owner, which is not available
    /// here. Callers handling `Owner` must resolve it externally.
    pub fn allows(&self, address: &Address) -> bool {
        match self {
            Self::Public => true,
            // Owner and ProofGated both return false here: callers must resolve externally.
            Self::Owner | Self::ProofGated { .. } => false,
            Self::Explicit { allowed } => allowed.contains(address)
        }
    }
}

// ============================================================
// SELECTIVE DISCLOSURE
// ============================================================

/// Configuration for controlled field-level disclosure.
///
/// Allows owners to prove specific properties of their private objects
/// to authorized parties without revealing the complete object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SelectiveDisclosure {
    /// Whether selective disclosure is enabled for this object.
    pub enabled: bool,

    /// Which fields (by name) can be selectively disclosed.
    pub disclosable_fields: Vec<String>,

    /// Disclosure conditions: field name → address that can request disclosure.
    pub disclosure_grants: HashMap<String, Vec<Address>>,

    /// Whether ZK proofs are required for disclosure (vs plaintext reveal).
    pub require_zk_proof: bool,
}

impl SelectiveDisclosure {
    /// No selective disclosure allowed.
    pub fn none() -> Self {
        Self {
            enabled: false,
            disclosable_fields: Vec::new(),
            disclosure_grants: HashMap::new(),
            require_zk_proof: false,
        }
    }

    /// Selective disclosure with specific fields enabled.
    pub fn for_fields(fields: Vec<String>) -> Self {
        Self {
            enabled: true,
            disclosable_fields: fields,
            disclosure_grants: HashMap::new(),
            require_zk_proof: false,
        }
    }

    /// Check if `address` can request disclosure of `field`.
    pub fn can_disclose_to(&self, field: &str, address: &Address) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.disclosable_fields.iter().any(|f| f == field) {
            return false;
        }
        self.disclosure_grants
            .get(field)
            .is_some_and(|addrs| addrs.contains(address))
    }
}

// ============================================================
// PRIVACY CONTEXT
// ============================================================

/// The privacy context for an execution session.
///
/// Tracks the effective privacy level for the current execution and
/// enforces boundaries when operations cross privacy levels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyContext {
    /// The privacy level of the current execution context.
    pub level: PrivacyLevel,

    /// Whether this execution is happening inside a TEE enclave.
    pub in_tee: bool,

    /// TEE attestation nonce for this execution context.
    pub tee_nonce: Option<[u8; 32]>,

    /// Objects in this context and their privacy levels.
    pub object_privacy: HashMap<String, PrivacyLevel>,

    /// Whether cross-privacy interactions are permitted in this context.
    pub cross_privacy_enabled: bool,
}

impl PrivacyContext {
    /// Create a public execution context.
    pub fn public() -> Self {
        Self {
            level: PrivacyLevel::Public,
            in_tee: false,
            tee_nonce: None,
            object_privacy: HashMap::new(),
            cross_privacy_enabled: true,
        }
    }

    /// Create a private TEE execution context.
    pub fn private_tee(nonce: [u8; 32]) -> Self {
        Self {
            level: PrivacyLevel::Private,
            in_tee: true,
            tee_nonce: Some(nonce),
            object_privacy: HashMap::new(),
            cross_privacy_enabled: false,
        }
    }

    /// Register an object's privacy level in this context.
    pub fn register_object(&mut self, object_id: String, level: PrivacyLevel) {
        let effective = self.level.max(level);
        self.object_privacy.insert(object_id, effective);
    }

    /// Check if executing at this privacy level requires TEE.
    pub fn requires_tee(&self) -> bool {
        self.level.requires_tee()
    }
}

impl Default for PrivacyContext {
    fn default() -> Self {
        Self::public()
    }
}

// ============================================================
// CROSS-PRIVACY COORDINATION
// ============================================================

/// Configuration for coordinated operations that cross privacy boundaries.
///
/// When an operation involves objects at different privacy levels, this
/// configuration controls how the boundary is mediated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossPrivacyCoordination {
    /// The highest privacy level among participating objects.
    pub effective_level: PrivacyLevel,

    /// How information flows from private to public contexts.
    pub disclosure_mode: CrossPrivacyDisclosureMode,

    /// Whether ZK proofs are used to mediate the boundary crossing.
    pub use_zk_proof: bool,

    /// Whether TEE-to-TEE secure channels are used for coordination.
    pub use_secure_channel: bool,
}

/// How information can flow across a privacy boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrossPrivacyDisclosureMode {
    /// Only cryptographic commitments are exposed (no plaintext).
    CommitmentOnly,
    /// ZK proofs of specific properties are exposed.
    ZeroKnowledge,
    /// Selective field disclosure with authorization.
    SelectiveField,
    /// Full disclosure to explicitly authorized parties.
    FullToAuthorized,
}

// ============================================================
// PRIVACY BOUNDARY
// ============================================================

/// Represents a boundary between execution contexts at different privacy levels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBoundary {
    /// Privacy level of the inner (more private) context.
    pub inner_level: PrivacyLevel,

    /// Privacy level of the outer (less private) context.
    pub outer_level: PrivacyLevel,

    /// Permitted crossing modes for this boundary.
    pub permitted_modes: Vec<CrossPrivacyDisclosureMode>,
}

impl PrivacyBoundary {
    /// Returns `true` if a crossing from inner to outer is permissible.
    pub fn allows_crossing(&self) -> bool {
        !self.permitted_modes.is_empty()
    }
}

// ============================================================
// PRIVACY-PRESERVING PROOF
// ============================================================

/// A proof that a private operation occurred correctly, without revealing inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPreservingProof {
    /// Type of proof (ZK, TEE attestation, commitment).
    pub proof_type: PrivacyProofType,

    /// Serialized proof bytes.
    pub proof_bytes: Vec<u8>,

    /// Public inputs to the proof (does not reveal private data).
    pub public_inputs: Vec<Vec<u8>>,

    /// Statement being proven (human-readable description).
    pub statement: String,
}

/// Type of privacy-preserving proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyProofType {
    /// Zero-knowledge proof.
    ZeroKnowledge,
    /// TEE attestation.
    TeeAttestation,
    /// Cryptographic commitment.
    Commitment,
    /// Composite proof combining multiple techniques.
    Composite,
}

// ============================================================
// MIXED PRIVACY EXECUTION
// ============================================================

/// Configuration for an execution that spans multiple privacy levels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixedPrivacyExecution {
    /// Map from object identifier to its privacy level.
    pub object_levels: HashMap<String, PrivacyLevel>,

    /// The computed effective level (maximum of all object levels).
    pub effective_level: PrivacyLevel,

    /// Whether separate TEE contexts are used per privacy level.
    pub isolated_contexts: bool,
}

impl MixedPrivacyExecution {
    /// Create a mixed privacy execution plan from object privacy requirements.
    pub fn from_objects(objects: HashMap<String, PrivacyLevel>) -> Self {
        let effective = objects
            .values()
            .copied()
            .max()
            .unwrap_or(PrivacyLevel::Public);

        let isolated = objects.values().any(|l| *l != effective);

        Self {
            object_levels: objects,
            effective_level: effective,
            isolated_contexts: isolated,
        }
    }
}

// ============================================================
// TEE REQUIREMENT
// ============================================================

/// Specifies what type of TEE is required for operating on a private object.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeRequirement {
    /// Any supported TEE platform is acceptable.
    AnyPlatform,
    /// Specific TEE platform required.
    SpecificPlatform(String),
    /// TEE with anti-snooping protection required.
    WithAntiSnooping,
    /// Multi-TEE coordination required.
    MultiTee {
        /// Minimum number of TEE instances required for coordination.
        min_instances: u32,
    },
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_level_ordering() {
        assert!(PrivacyLevel::Public < PrivacyLevel::Protected);
        assert!(PrivacyLevel::Protected < PrivacyLevel::Private);
        assert!(PrivacyLevel::Private < PrivacyLevel::Confidential);
    }

    #[test]
    fn privacy_level_tee_requirements() {
        assert!(!PrivacyLevel::Public.requires_tee());
        assert!(!PrivacyLevel::Protected.requires_tee());
        assert!(PrivacyLevel::Private.requires_tee());
        assert!(PrivacyLevel::Confidential.requires_tee());
    }

    #[test]
    fn privacy_level_anti_snooping() {
        assert!(!PrivacyLevel::Private.requires_anti_snooping());
        assert!(PrivacyLevel::Confidential.requires_anti_snooping());
    }

    #[test]
    fn privacy_level_max() {
        assert_eq!(
            PrivacyLevel::Public.max(PrivacyLevel::Private),
            PrivacyLevel::Private
        );
    }

    #[test]
    fn access_policy_public_allows_all() {
        let any_addr = Address([0xABu8; 32]);
        assert!(AccessPolicy::Public.allows(&any_addr));
    }

    #[test]
    fn access_policy_explicit_allows_listed() {
        let allowed = Address([1u8; 32]);
        let denied = Address([2u8; 32]);
        let policy = AccessPolicy::Explicit {
            allowed: vec![allowed],
        };
        assert!(policy.allows(&allowed));
        assert!(!policy.allows(&denied));
    }

    #[test]
    fn privacy_policy_public_default() {
        let p = PrivacyPolicy::public();
        assert_eq!(p.level, PrivacyLevel::Public);
        assert!(p.cross_privacy_allowed);
        assert!(p.tee_requirements.is_none());
    }

    #[test]
    fn selective_disclosure_disabled_by_default() {
        let sd = SelectiveDisclosure::none();
        let addr = Address([1u8; 32]);
        assert!(!sd.can_disclose_to("field1", &addr));
    }

    #[test]
    fn mixed_privacy_effective_level() {
        let mut objects = HashMap::new();
        objects.insert("obj1".into(), PrivacyLevel::Public);
        objects.insert("obj2".into(), PrivacyLevel::Private);
        let exec = MixedPrivacyExecution::from_objects(objects);
        assert_eq!(exec.effective_level, PrivacyLevel::Private);
        assert!(exec.isolated_contexts);
    }

    #[test]
    fn privacy_level_gas_multiplier_increases() {
        assert!(
            PrivacyLevel::Public.gas_multiplier()
                < PrivacyLevel::Private.gas_multiplier()
        );
        assert!(
            PrivacyLevel::Private.gas_multiplier()
                < PrivacyLevel::Confidential.gas_multiplier()
        );
    }
}
