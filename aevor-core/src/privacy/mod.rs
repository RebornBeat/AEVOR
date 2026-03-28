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
    use std::collections::HashMap;

    fn addr(n: u8) -> Address { Address([n; 32]) }

    // ── PrivacyLevel hierarchy ────────────────────────────────────────────
    // Whitepaper: "object-level privacy policies, granular confidentiality control"

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
        assert_eq!(PrivacyLevel::Public.max(PrivacyLevel::Private), PrivacyLevel::Private);
        assert_eq!(PrivacyLevel::Confidential.max(PrivacyLevel::Public), PrivacyLevel::Confidential);
    }

    #[test]
    fn privacy_level_at_least() {
        assert!(PrivacyLevel::Private.at_least(PrivacyLevel::Public));
        assert!(PrivacyLevel::Private.at_least(PrivacyLevel::Private));
        assert!(!PrivacyLevel::Public.at_least(PrivacyLevel::Private));
    }

    #[test]
    fn privacy_level_gas_multiplier_increases() {
        assert!(PrivacyLevel::Public.gas_multiplier() < PrivacyLevel::Private.gas_multiplier());
        assert!(PrivacyLevel::Private.gas_multiplier() < PrivacyLevel::Confidential.gas_multiplier());
    }

    // ── AccessPolicy ─────────────────────────────────────────────────────

    #[test]
    fn access_policy_public_allows_all() {
        assert!(AccessPolicy::Public.allows(&addr(0xAB)));
        assert!(AccessPolicy::Public.allows(&addr(0)));
    }

    #[test]
    fn access_policy_explicit_allows_listed_denies_others() {
        let policy = AccessPolicy::Explicit { allowed: vec![addr(1)] };
        assert!(policy.allows(&addr(1)));
        assert!(!policy.allows(&addr(2)));
    }

    // ── PrivacyPolicy object-level declarations ───────────────────────────
    // Whitepaper: "each blockchain object can specify its own privacy characteristics"

    #[test]
    fn privacy_policy_public_default_open_access() {
        let p = PrivacyPolicy::public();
        assert_eq!(p.level, PrivacyLevel::Public);
        assert!(p.cross_privacy_allowed);
        assert!(p.tee_requirements.is_none());
        assert!(p.has_read_access(&addr(0xFF))); // anyone can read
    }

    #[test]
    fn privacy_policy_private_restricts_access_and_requires_tee() {
        let owner = addr(1);
        let p = PrivacyPolicy::private(owner);
        assert_eq!(p.level, PrivacyLevel::Private);
        assert!(!p.cross_privacy_allowed);
        assert!(p.tee_requirements.is_some());
        assert!(p.has_read_access(&owner));
        assert!(!p.has_read_access(&addr(99)));
    }

    #[test]
    fn privacy_policy_confidential_anti_snooping_required() {
        let owner = addr(2);
        let p = PrivacyPolicy::confidential(owner);
        assert_eq!(p.level, PrivacyLevel::Confidential);
        assert_eq!(p.tee_requirements, Some(TeeRequirement::WithAntiSnooping));
        assert!(p.level.requires_anti_snooping());
    }

    // ── SelectiveDisclosure ───────────────────────────────────────────────
    // Whitepaper: "selective disclosure with authorization"

    #[test]
    fn selective_disclosure_disabled_by_default() {
        let sd = SelectiveDisclosure::none();
        assert!(!sd.can_disclose_to("field1", &addr(1)));
    }

    // ── MixedPrivacyExecution ─────────────────────────────────────────────
    // Whitepaper: "Mixed privacy coordination enables applications to implement
    // business logic that spans both confidential and transparent operations."

    #[test]
    fn mixed_privacy_effective_level_is_max_of_all_objects() {
        let mut objects = HashMap::new();
        objects.insert("public_token".into(), PrivacyLevel::Public);
        objects.insert("private_balance".into(), PrivacyLevel::Private);
        let exec = MixedPrivacyExecution::from_objects(objects);
        assert_eq!(exec.effective_level, PrivacyLevel::Private);
        assert!(exec.isolated_contexts); // different levels → isolation needed
    }

    #[test]
    fn mixed_privacy_all_same_level_not_isolated() {
        let mut objects = HashMap::new();
        objects.insert("obj1".into(), PrivacyLevel::Public);
        objects.insert("obj2".into(), PrivacyLevel::Public);
        let exec = MixedPrivacyExecution::from_objects(objects);
        assert_eq!(exec.effective_level, PrivacyLevel::Public);
        assert!(!exec.isolated_contexts);
    }

    #[test]
    fn mixed_privacy_empty_objects_defaults_to_public() {
        let exec = MixedPrivacyExecution::from_objects(HashMap::new());
        assert_eq!(exec.effective_level, PrivacyLevel::Public);
    }

    // ── CrossPrivacyCoordination ──────────────────────────────────────────
    // Whitepaper: "business logic that spans both confidential and transparent
    // operations within the same execution context"

    #[test]
    fn cross_privacy_coordination_zk_mode() {
        let coord = CrossPrivacyCoordination {
            effective_level: PrivacyLevel::Private,
            disclosure_mode: CrossPrivacyDisclosureMode::ZeroKnowledge,
            use_zk_proof: true,
            use_secure_channel: false,
        };
        assert!(coord.use_zk_proof);
        assert_eq!(coord.disclosure_mode, CrossPrivacyDisclosureMode::ZeroKnowledge);
    }

    #[test]
    fn cross_privacy_coordination_secure_channel_mode() {
        let coord = CrossPrivacyCoordination {
            effective_level: PrivacyLevel::Confidential,
            disclosure_mode: CrossPrivacyDisclosureMode::CommitmentOnly,
            use_zk_proof: false,
            use_secure_channel: true,
        };
        assert!(coord.use_secure_channel);
    }

    // ── PrivacyBoundary ───────────────────────────────────────────────────

    #[test]
    fn privacy_boundary_allows_crossing_when_modes_present() {
        let b = PrivacyBoundary {
            inner_level: PrivacyLevel::Private,
            outer_level: PrivacyLevel::Public,
            permitted_modes: vec![CrossPrivacyDisclosureMode::ZeroKnowledge],
        };
        assert!(b.allows_crossing());
    }

    #[test]
    fn privacy_boundary_no_crossing_when_no_modes() {
        let b = PrivacyBoundary {
            inner_level: PrivacyLevel::Confidential,
            outer_level: PrivacyLevel::Private,
            permitted_modes: vec![],
        };
        assert!(!b.allows_crossing());
    }

    // ── PrivacyPreservingProof ────────────────────────────────────────────
    // Whitepaper: "privacy-preserving proof ... without revealing inputs"

    #[test]
    fn privacy_proof_tee_attestation_type() {
        let proof = PrivacyPreservingProof {
            proof_type: PrivacyProofType::TeeAttestation,
            proof_bytes: vec![0xAB; 64],
            public_inputs: vec![vec![1, 2, 3]],
            statement: "execution correct".into(),
        };
        assert_eq!(proof.proof_type, PrivacyProofType::TeeAttestation);
        assert!(!proof.proof_bytes.is_empty());
        assert!(!proof.public_inputs.is_empty());
    }

    #[test]
    fn privacy_proof_composite_combines_techniques() {
        let proof = PrivacyPreservingProof {
            proof_type: PrivacyProofType::Composite,
            proof_bytes: vec![1, 2],
            public_inputs: vec![],
            statement: "combined zk + tee".into(),
        };
        assert_eq!(proof.proof_type, PrivacyProofType::Composite);
    }

    // ── TeeRequirement ────────────────────────────────────────────────────

    #[test]
    fn tee_requirement_multi_tee_min_instances() {
        let req = TeeRequirement::MultiTee { min_instances: 3 };
        assert_eq!(req, TeeRequirement::MultiTee { min_instances: 3 });
        assert_ne!(req, TeeRequirement::AnyPlatform);
    }
}

// ============================================================
// CONDITIONAL AND PROGRESSIVE DISCLOSURE
// ============================================================

/// A disclosure that activates only when a specified logical condition is satisfied.
///
/// Conditions are expressed as application-defined identifiers resolved through
/// consensus — no external clock or authority required. The disclosure itself
/// uses cryptographic enforcement: once the condition is met, the authorized
/// party can derive the disclosed information; before it is met, they cannot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalDisclosure {
    /// The field being conditionally disclosed.
    pub field: String,
    /// Application-defined condition identifier (e.g. "auction_closed", "payment_confirmed").
    pub condition_id: String,
    /// Addresses authorized to receive the disclosure once the condition is met.
    pub authorized: Vec<Address>,
    /// Whether a ZK proof is required to verify the condition was met.
    pub require_condition_proof: bool,
}

impl ConditionalDisclosure {
    /// Create a conditional disclosure that fires when `condition_id` is satisfied.
    pub fn new(field: impl Into<String>, condition_id: impl Into<String>, authorized: Vec<Address>) -> Self {
        Self {
            field: field.into(),
            condition_id: condition_id.into(),
            authorized,
            require_condition_proof: false,
        }
    }

    /// Whether `address` is authorized to receive the disclosure.
    pub fn is_authorized(&self, address: &Address) -> bool {
        self.authorized.contains(address)
    }
}

/// A disclosure that evolves through logical ordering stages.
///
/// Each stage increases the privacy level from confidential toward more transparent,
/// driven by dependency-based ordering through blockchain consensus time authority —
/// not by wall-clock time or external triggers.
///
/// Example use case: confidential bidding → disclosed winner → public final price.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressiveDisclosure {
    /// Ordered stages from most private to most public.
    pub stages: Vec<DisclosureStage>,
    /// Current active stage index.
    pub current_stage: usize,
}

/// A single stage in a progressive disclosure sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureStage {
    /// Human-readable name for this stage.
    pub name: String,
    /// Privacy level at this stage.
    pub level: PrivacyLevel,
    /// Fields disclosed at this stage (cumulative — each stage adds to previous).
    pub disclosed_fields: Vec<String>,
    /// Logical sequence number at which this stage activates.
    /// Uses blockchain consensus time authority, not wall-clock time.
    pub activates_at_sequence: u64,
}

impl ProgressiveDisclosure {
    /// Create a progressive disclosure with the given ordered stages.
    pub fn new(stages: Vec<DisclosureStage>) -> Self {
        Self { stages, current_stage: 0 }
    }

    /// Advance to the next stage if the given consensus sequence number qualifies.
    /// Returns `true` if the stage advanced.
    pub fn advance_if_ready(&mut self, consensus_sequence: u64) -> bool {
        let next = self.current_stage + 1;
        if next < self.stages.len()
            && self.stages[next].activates_at_sequence <= consensus_sequence
        {
            self.current_stage = next;
            return true;
        }
        false
    }

    /// The privacy level of the current stage.
    pub fn current_level(&self) -> PrivacyLevel {
        self.stages.get(self.current_stage)
            .map_or(PrivacyLevel::Public, |s| s.level)
    }

    /// Fields disclosed in the current stage.
    pub fn current_disclosed_fields(&self) -> &[String] {
        self.stages.get(self.current_stage)
            .map_or(&[], |s| s.disclosed_fields.as_slice())
    }
}

// ============================================================
// PRIVACY INHERITANCE
// ============================================================

/// Privacy inheritance rule for composite objects.
///
/// When a complex object contains components with different privacy requirements,
/// inheritance determines the effective privacy of the whole — ensuring that
/// confidential components remain protected even when the containing object
/// is accessed at a lower privacy level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyInheritanceRule {
    /// Effective privacy = maximum of all component levels (most restrictive wins).
    MaxOfComponents,
    /// Effective privacy = the explicitly specified level, regardless of components.
    /// Callers must ensure components are handled appropriately.
    Explicit(PrivacyLevel),
    /// Effective privacy = privacy of the owning context.
    InheritFromContext,
}

impl PrivacyInheritanceRule {
    /// Resolve the effective privacy level for a composite object.
    pub fn resolve(&self, component_levels: &[PrivacyLevel], context_level: PrivacyLevel) -> PrivacyLevel {
        match self {
            Self::MaxOfComponents => component_levels.iter().copied().max().unwrap_or(PrivacyLevel::Public),
            Self::Explicit(level) => *level,
            Self::InheritFromContext => context_level,
        }
    }
}

// ============================================================
// CROSS-NETWORK PRIVACY
// ============================================================

/// Privacy configuration for communication crossing network boundaries.
///
/// When transactions or data flow between different AEVOR networks or subnets,
/// this configuration controls how privacy levels are preserved across the boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossNetworkPrivacyConfig {
    /// Minimum privacy level that can cross this boundary.
    /// Objects more private than `max_crossing_level` cannot cross.
    pub max_crossing_level: PrivacyLevel,
    /// Whether metadata protection is applied to cross-network messages.
    pub metadata_protection: MetadataProtectionLevel,
    /// Whether ZK proofs are required to verify privacy compliance across the boundary.
    pub require_privacy_proof: bool,
    /// Whether cross-network audit logging is enabled (application-layer policy).
    pub audit_crossings: bool,
}

impl Default for CrossNetworkPrivacyConfig {
    fn default() -> Self {
        Self {
            max_crossing_level: PrivacyLevel::Protected,
            metadata_protection: MetadataProtectionLevel::Standard,
            require_privacy_proof: false,
            audit_crossings: true,
        }
    }
}

/// Level of metadata protection for cross-network communication.
///
/// Metadata includes message sizes, timing, sender/recipient patterns, and
/// routing information — all of which can reveal sensitive information even
/// when message content is encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetadataProtectionLevel {
    /// No metadata protection (transparent routing).
    None,
    /// Basic: message sizes normalized, basic timing jitter applied.
    Basic,
    /// Standard: size normalization + timing jitter + routing obfuscation.
    Standard,
    /// Maximum: all standard protections + cover traffic + topology privacy.
    Maximum,
}

impl MetadataProtectionLevel {
    /// Returns `true` if timing obfuscation is applied at this level.
    pub fn has_timing_protection(&self) -> bool {
        matches!(self, Self::Standard | Self::Maximum)
    }

    /// Returns `true` if cover traffic is generated at this level.
    pub fn has_cover_traffic(&self) -> bool {
        matches!(self, Self::Maximum)
    }
}

// ============================================================
// ADDITIONAL TESTS FOR NEW TYPES
// ============================================================

#[cfg(test)]
mod extended_tests {
    use super::*;

    fn addr(n: u8) -> Address { Address([n; 32]) }

    // ── ConditionalDisclosure ─────────────────────────────────────────────
    // Whitepaper §16.5: "conditional selective disclosure enables information sharing
    // that depends on specific conditions being met through mathematical verification"

    #[test]
    fn conditional_disclosure_authorized_check() {
        let d = ConditionalDisclosure::new(
            "bid_amount",
            "auction_closed",
            vec![addr(1), addr(2)],
        );
        assert!(d.is_authorized(&addr(1)));
        assert!(!d.is_authorized(&addr(99)));
        assert_eq!(d.condition_id, "auction_closed");
        assert_eq!(d.field, "bid_amount");
    }

    #[test]
    fn conditional_disclosure_unauthorized_before_condition_met() {
        let d = ConditionalDisclosure::new("trade_price", "settlement_complete", vec![addr(5)]);
        // Unauthorized parties cannot receive disclosure even if condition were met
        assert!(!d.is_authorized(&addr(10)));
        assert!(d.is_authorized(&addr(5)));
    }

    // ── ProgressiveDisclosure ─────────────────────────────────────────────
    // Whitepaper §16.5: "progressive selective disclosure enables information sharing
    // policies that change based on logical ordering"

    #[test]
    fn progressive_disclosure_starts_at_most_private_stage() {
        let stages = vec![
            DisclosureStage { name: "bidding".into(), level: PrivacyLevel::Confidential, disclosed_fields: vec![], activates_at_sequence: 0 },
            DisclosureStage { name: "winner_disclosed".into(), level: PrivacyLevel::Private, disclosed_fields: vec!["winner".into()], activates_at_sequence: 100 },
            DisclosureStage { name: "public_result".into(), level: PrivacyLevel::Public, disclosed_fields: vec!["winner".into(), "price".into()], activates_at_sequence: 200 },
        ];
        let pd = ProgressiveDisclosure::new(stages);
        assert_eq!(pd.current_level(), PrivacyLevel::Confidential);
        assert!(pd.current_disclosed_fields().is_empty());
    }

    #[test]
    fn progressive_disclosure_advances_at_consensus_sequence() {
        let stages = vec![
            DisclosureStage { name: "private".into(), level: PrivacyLevel::Private, disclosed_fields: vec![], activates_at_sequence: 0 },
            DisclosureStage { name: "public".into(), level: PrivacyLevel::Public, disclosed_fields: vec!["result".into()], activates_at_sequence: 50 },
        ];
        let mut pd = ProgressiveDisclosure::new(stages);
        assert!(!pd.advance_if_ready(49)); // not yet
        assert_eq!(pd.current_level(), PrivacyLevel::Private);
        assert!(pd.advance_if_ready(50)); // exactly at threshold
        assert_eq!(pd.current_level(), PrivacyLevel::Public);
        assert_eq!(pd.current_disclosed_fields(), &["result".to_string()]);
    }

    #[test]
    fn progressive_disclosure_does_not_advance_past_last_stage() {
        let stages = vec![
            DisclosureStage { name: "only".into(), level: PrivacyLevel::Private, disclosed_fields: vec![], activates_at_sequence: 0 },
        ];
        let mut pd = ProgressiveDisclosure::new(stages);
        assert!(!pd.advance_if_ready(u64::MAX)); // no next stage
        assert_eq!(pd.current_stage, 0);
    }

    // ── PrivacyInheritanceRule ────────────────────────────────────────────
    // Whitepaper §16.8: "Privacy policy inheritance enables complex applications...
    // to specify privacy requirements for individual components while maintaining
    // overall policy consistency"

    #[test]
    fn privacy_inheritance_max_of_components_picks_most_restrictive() {
        let rule = PrivacyInheritanceRule::MaxOfComponents;
        let levels = [PrivacyLevel::Public, PrivacyLevel::Private, PrivacyLevel::Protected];
        assert_eq!(rule.resolve(&levels, PrivacyLevel::Public), PrivacyLevel::Private);
    }

    #[test]
    fn privacy_inheritance_explicit_ignores_components() {
        let rule = PrivacyInheritanceRule::Explicit(PrivacyLevel::Confidential);
        let levels = [PrivacyLevel::Public]; // even if components are public
        assert_eq!(rule.resolve(&levels, PrivacyLevel::Public), PrivacyLevel::Confidential);
    }

    #[test]
    fn privacy_inheritance_from_context_uses_context() {
        let rule = PrivacyInheritanceRule::InheritFromContext;
        let levels = [PrivacyLevel::Public];
        assert_eq!(rule.resolve(&levels, PrivacyLevel::Private), PrivacyLevel::Private);
    }

    #[test]
    fn privacy_inheritance_empty_components_defaults_to_public() {
        let rule = PrivacyInheritanceRule::MaxOfComponents;
        assert_eq!(rule.resolve(&[], PrivacyLevel::Public), PrivacyLevel::Public);
    }

    // ── CrossNetworkPrivacyConfig ─────────────────────────────────────────
    // Whitepaper §16.9: "Privacy-Preserving Cross-Network Communication"

    #[test]
    fn cross_network_privacy_default_allows_up_to_protected() {
        let cfg = CrossNetworkPrivacyConfig::default();
        assert_eq!(cfg.max_crossing_level, PrivacyLevel::Protected);
        assert!(cfg.audit_crossings);
    }

    #[test]
    fn cross_network_privacy_confidential_blocked_at_protected_boundary() {
        let cfg = CrossNetworkPrivacyConfig::default();
        // Confidential is more private than Protected — should not cross
        assert!(PrivacyLevel::Confidential > cfg.max_crossing_level);
    }

    // ── MetadataProtectionLevel ───────────────────────────────────────────
    // Whitepaper §16.9: "metadata protection ensures communication privacy extends
    // beyond message content to encompass communication patterns"

    #[test]
    fn metadata_protection_standard_has_timing_not_cover_traffic() {
        assert!(MetadataProtectionLevel::Standard.has_timing_protection());
        assert!(!MetadataProtectionLevel::Standard.has_cover_traffic());
    }

    #[test]
    fn metadata_protection_maximum_has_all_protections() {
        assert!(MetadataProtectionLevel::Maximum.has_timing_protection());
        assert!(MetadataProtectionLevel::Maximum.has_cover_traffic());
    }

    #[test]
    fn metadata_protection_basic_no_timing() {
        assert!(!MetadataProtectionLevel::Basic.has_timing_protection());
        assert!(!MetadataProtectionLevel::Basic.has_cover_traffic());
    }

    #[test]
    fn metadata_protection_none_no_protections() {
        assert!(!MetadataProtectionLevel::None.has_timing_protection());
        assert!(!MetadataProtectionLevel::None.has_cover_traffic());
    }
}
