//! Re-exports aevor-core crypto primitives with implementations attached.

pub use aevor_core::crypto::{
    AggregateSignature, BlsSignature as CoreBlsSignature,
    CommitmentOpening, CommitmentProof, CommitmentScheme,
    CrossPlatformAttestation, CryptoProof, CryptoProofType,
    ProvingSystem, SecurityClaims, ZeroKnowledgeProof,
};
