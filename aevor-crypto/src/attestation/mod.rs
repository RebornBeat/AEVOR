//! Shared attestation signing primitive.
//!
//! The TEE layer (`aevor-tee`) and the consensus layer (`aevor-consensus`) both
//! verify TEE attestations, over slightly different field sets. To keep a single
//! source of truth for the *cryptography* (the trust-root key and the
//! sign/verify implementation), both layers build their own canonical body bytes
//! and call [`sim_sign`] / [`sim_verify`] here. Only the field serialization —
//! which is inherent to each layer's type — differs; the key and the signature
//! scheme cannot drift.

use crate::signatures::Ed25519KeyPair;

/// Fixed simulation attestation key seed.
///
/// This is the simulation stand-in for a hardware vendor's attestation root.
/// It is deliberately well-known and carries **no real hardware trust**: it lets
/// simulation builds exercise the real signature-verification path, while the
/// production-vs-simulation *acceptance* policy is enforced at the consensus
/// layer (reports carry `is_production = false`). Production builds verify a real
/// vendor certificate chain instead.
pub const SIM_ATTESTATION_SEED: [u8; 32] = *b"aevor-tee-simulation-attest-key!";

fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed(SIM_ATTESTATION_SEED)
}

/// Sign an attestation canonical body with the simulation attestation key.
#[must_use]
pub fn sim_sign(body: &[u8]) -> [u8; 64] {
    key().sign(body).0 .0
}

/// Verify an attestation canonical-body signature under the simulation key.
#[must_use]
pub fn sim_verify(body: &[u8], signature: &[u8; 64]) -> bool {
    let k = key();
    Ed25519KeyPair::verify_raw(&k.public_key_bytes(), body, signature)
}

// ── Consensus attestation evidence (shared by aevor-consensus + aevor-client) ──

use aevor_core::consensus::{AttestationEvidence, TeeAttestationPlatform};
use aevor_core::primitives::Hash256;

fn evidence_platform_tag(p: TeeAttestationPlatform) -> u8 {
    match p {
        TeeAttestationPlatform::IntelSgx => 1,
        TeeAttestationPlatform::AmdSev => 2,
        TeeAttestationPlatform::ArmTrustZone => 3,
        TeeAttestationPlatform::RiscvKeystone => 4,
        TeeAttestationPlatform::AwsNitro => 5,
    }
}

/// Canonical, signature-free body for a consensus [`AttestationEvidence`].
/// [`seal_evidence`] and [`verify_evidence`] both derive the signed bytes from
/// this one function, so signing and verification cannot drift — and the
/// consensus layer and the client verify evidence identically.
#[must_use]
pub fn canonical_evidence_body(e: &AttestationEvidence) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + 32 + 32 + 1 + 4);
    m.push(evidence_platform_tag(e.platform));
    m.extend_from_slice(&e.code_measurement.0);
    m.extend_from_slice(&e.nonce);
    m.push(u8::from(e.is_production));
    m.extend_from_slice(&e.svn.to_le_bytes());
    m
}

/// Seal attestation evidence by signing its canonical body.
#[must_use]
pub fn seal_evidence(mut e: AttestationEvidence) -> AttestationEvidence {
    e.raw_report = sim_sign(&canonical_evidence_body(&e)).to_vec();
    e
}

/// Verify sealed attestation evidence: a valid signature over its canonical body
/// plus a non-degenerate code measurement. Shared by the consensus layer and
/// the client so both accept/reject identically.
#[must_use]
pub fn verify_evidence(e: &AttestationEvidence) -> bool {
    if e.code_measurement == Hash256::ZERO {
        return false;
    }
    let sig: [u8; 64] = match e.raw_report.as_slice().try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    sim_verify(&canonical_evidence_body(e), &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrips() {
        let body = b"platform|measurement|nonce";
        let sig = sim_sign(body);
        assert!(sim_verify(body, &sig));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let sig = sim_sign(b"original body");
        assert!(!sim_verify(b"tampered body", &sig));
    }
}
