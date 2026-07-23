//! Real AWS Nitro Enclaves attestation-document verification (pure Rust).
//!
//! An attestation document is a CBOR-encoded `COSE_Sign1` object — a 4-element
//! array `[protected, unprotected, payload, signature]` (optionally tagged 18).
//! The `payload` is itself a CBOR map with `module_id`, `timestamp`, `digest`,
//! `pcrs`, `certificate` (DER — the leaf signing cert), `cabundle` (`[DER]` up to
//! the AWS Nitro root), and optional `public_key` / `user_data` / `nonce`.
//!
//! Verification, per the AWS Nitro attestation process:
//! 1. decode CBOR → `COSE_Sign1` and its payload → the attestation document;
//! 2. validate the certificate chain `leaf → cabundle → pinned AWS Nitro root`;
//! 3. verify the `COSE_Sign1` ES384 signature with the leaf certificate's P-384
//!    key over the reconstructed `Sig_structure`;
//! 4. check the PCRs against the network-agreed registry (which enclave image is
//!    allowed to produce blocks);
//! 5. check `user_data` binds the expected payload and the document is fresh.
//!
//! This module builds and runs anywhere with no enclave — it is the verifier side
//! every validator runs. The producer side (`super::generate_report`) needs the
//! NSM device and only executes inside an enclave.

use ciborium::value::Value;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::{TeeError, TeeResult};

/// SHA-256 fingerprint of the AWS Nitro Enclaves root certificate (commercial
/// partitions), as published by AWS. The operator supplies the root certificate
/// DER (from `https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip`);
/// this verifier pins trust to this fingerprint, so a substituted root is
/// rejected. AWS's published value:
/// `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`.
pub const AWS_NITRO_ROOT_SHA256_FINGERPRINT: [u8; 32] = [
    0x64, 0x1A, 0x03, 0x21, 0xA3, 0xE2, 0x44, 0xEF, 0xE4, 0x56, 0x46, 0x31, 0x95, 0xD6, 0x06, 0x31,
    0x7E, 0xD7, 0xCD, 0xCC, 0x3C, 0x17, 0x56, 0xE0, 0x98, 0x93, 0xF3, 0xC6, 0x8F, 0x79, 0xBB, 0x5B,
];

/// A parsed, cryptographically verified Nitro attestation document.
#[derive(Clone, Debug)]
pub struct VerifiedAttestation {
    /// All locked PCRs at attestation time (index → measurement).
    pub pcrs: std::collections::BTreeMap<u32, Vec<u8>>,
    /// Application-bound data (AEVOR puts the `ExecutionAttestation` body here).
    pub user_data: Vec<u8>,
    /// Freshness nonce echoed from the attestation request.
    pub nonce: Vec<u8>,
    /// Document creation time (ms since UNIX epoch).
    pub timestamp_ms: u64,
    /// Issuing Nitro hypervisor module id.
    pub module_id: String,
}

fn fail(reason: impl Into<String>) -> TeeError {
    TeeError::AttestationFailed { reason: reason.into() }
}

fn as_bytes(v: &Value) -> TeeResult<Vec<u8>> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(fail("expected CBOR byte string")),
    }
}

/// Decode the top-level `COSE_Sign1` into `(protected_bytes, payload_bytes,
/// signature_bytes)`. Accepts the tagged (tag 18) or untagged array form.
fn decode_cose_sign1(doc: &[u8]) -> TeeResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let value: Value =
        ciborium::de::from_reader(doc).map_err(|e| fail(format!("CBOR decode: {e}")))?;
    // Unwrap CBOR tag 18 if present.
    let arr = match value {
        Value::Tag(18, inner) => *inner,
        other => other,
    };
    let Value::Array(items) = arr else {
        return Err(fail("COSE_Sign1 is not a CBOR array"));
    };
    if items.len() != 4 {
        return Err(fail("COSE_Sign1 array must have 4 elements"));
    }
    let protected = as_bytes(&items[0])?;
    // items[1] is the unprotected header map (ignored).
    let payload = as_bytes(&items[2])?;
    let signature = as_bytes(&items[3])?;
    Ok((protected, payload, signature))
}

/// Parse the attestation-document payload (a CBOR map).
fn parse_document(payload: &[u8]) -> TeeResult<(VerifiedAttestation, Vec<u8>, Vec<Vec<u8>>)> {
    let value: Value =
        ciborium::de::from_reader(payload).map_err(|e| fail(format!("payload CBOR: {e}")))?;
    let Value::Map(entries) = value else {
        return Err(fail("attestation document is not a CBOR map"));
    };
    let get = |key: &str| entries.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key)).map(|(_, v)| v);

    let module_id = match get("module_id") {
        Some(Value::Text(t)) => t.clone(),
        _ => return Err(fail("missing module_id")),
    };
    let timestamp_ms = match get("timestamp") {
        Some(Value::Integer(i)) => u64::try_from(i128::from(*i)).map_err(|_| fail("bad timestamp"))?,
        _ => return Err(fail("missing timestamp")),
    };
    let certificate = match get("certificate") {
        Some(v) => as_bytes(v)?,
        None => return Err(fail("missing certificate")),
    };
    let mut cabundle = Vec::new();
    match get("cabundle") {
        Some(Value::Array(items)) => {
            for c in items {
                cabundle.push(as_bytes(c)?);
            }
        }
        _ => return Err(fail("missing cabundle")),
    }
    let mut pcrs = std::collections::BTreeMap::new();
    match get("pcrs") {
        Some(Value::Map(items)) => {
            for (k, v) in items {
                if let Value::Integer(idx) = k {
                    let idx = u32::try_from(i128::from(*idx)).map_err(|_| fail("bad PCR index"))?;
                    pcrs.insert(idx, as_bytes(v)?);
                }
            }
        }
        _ => return Err(fail("missing pcrs")),
    }
    let user_data = match get("user_data") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };
    let nonce = match get("nonce") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };

    Ok((
        VerifiedAttestation { pcrs, user_data, nonce, timestamp_ms, module_id },
        certificate,
        cabundle,
    ))
}

/// Validate the certificate chain: the root (first cabundle entry) must match the
/// pinned AWS Nitro root fingerprint, each certificate must be signed by the next
/// one up, and the leaf (the document's `certificate`) must be signed by the last
/// cabundle entry. Returns the leaf's DER for signature verification.
fn verify_chain(leaf_der: &[u8], cabundle: &[Vec<u8>]) -> TeeResult<()> {
    if cabundle.is_empty() {
        return Err(fail("empty cabundle"));
    }
    // Pin the root.
    let root_fp: [u8; 32] = Sha256::digest(&cabundle[0]).into();
    if root_fp != AWS_NITRO_ROOT_SHA256_FINGERPRINT {
        return Err(fail("cabundle root does not match the pinned AWS Nitro root fingerprint"));
    }
    // Full chain in issuing order: [root, ...intermediates, leaf].
    let mut chain_der: Vec<&[u8]> = cabundle.iter().map(std::vec::Vec::as_slice).collect();
    chain_der.push(leaf_der);

    // Each certificate must be signed by its issuer (the previous one).
    for i in 1..chain_der.len() {
        let (_, cert) = X509Certificate::from_der(chain_der[i])
            .map_err(|e| fail(format!("parse cert {i}: {e}")))?;
        let (_, issuer) = X509Certificate::from_der(chain_der[i - 1])
            .map_err(|e| fail(format!("parse issuer {i}: {e}")))?;
        cert.verify_signature(Some(issuer.public_key()))
            .map_err(|e| fail(format!("chain link {i} signature invalid: {e}")))?;
    }
    Ok(())
}

/// Verify the `COSE_Sign1` ES384 signature using the leaf certificate's P-384 key.
/// The signed message is the canonical `Sig_structure`:
/// `["Signature1", protected, external_aad (empty), payload]`, CBOR-encoded.
fn verify_cose_signature(
    leaf_der: &[u8],
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> TeeResult<()> {
    use p384::ecdsa::signature::Verifier as _;

    // Reconstruct and encode the Sig_structure.
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut signed_bytes = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut signed_bytes)
        .map_err(|e| fail(format!("encode Sig_structure: {e}")))?;

    // Extract the P-384 public key (SEC1 point) from the leaf certificate.
    let (_, leaf) =
        X509Certificate::from_der(leaf_der).map_err(|e| fail(format!("parse leaf: {e}")))?;
    let spki = leaf.public_key();
    let point = spki.subject_public_key.data.as_ref();
    let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
        .map_err(|e| fail(format!("leaf key not P-384: {e}")))?;

    // COSE carries a fixed-width r‖s signature (96 bytes for P-384).
    let sig = p384::ecdsa::Signature::from_slice(signature)
        .map_err(|e| fail(format!("bad ES384 signature encoding: {e}")))?;

    verifying_key
        .verify(&signed_bytes, &sig)
        .map_err(|e| fail(format!("attestation signature invalid: {e}")))
}

/// Full verification of an AWS Nitro attestation document. On success returns the
/// parsed, verified document. This performs steps 1–3 (decode, chain, signature);
/// the caller checks PCRs / `user_data` / freshness against its policy (see
/// [`VerifiedAttestation`] and [`check_policy`]).
///
/// # Errors
/// Returns [`TeeError::AttestationFailed`] on any malformed field, a chain that
/// does not root in the pinned AWS Nitro root, or an invalid signature.
pub fn verify_document(doc: &[u8]) -> TeeResult<VerifiedAttestation> {
    let (protected, payload, signature) = decode_cose_sign1(doc)?;
    let (verified, leaf_der, cabundle) = parse_document(&payload)?;
    verify_chain(&leaf_der, &cabundle)?;
    verify_cose_signature(&leaf_der, &protected, &payload, &signature)?;
    Ok(verified)
}

/// Policy check on an already cryptographically verified document: the enclave
/// measurements (PCR0/1/2, and PCR8 when a signing cert is enforced) must be in
/// the accepted set, `user_data` must equal the expected bound payload, and the
/// document must be no older than `max_age_ms`.
///
/// # Errors
/// Returns [`TeeError::AttestationFailed`] if any measurement is not accepted, the
/// bound data differs, or the document is stale.
pub fn check_policy(
    doc: &VerifiedAttestation,
    accepted: &crate::nitro::MeasurementRegistry,
    expected_user_data: &[u8],
    now_ms: u64,
    max_age_ms: u64,
) -> TeeResult<()> {
    if doc.user_data != expected_user_data {
        return Err(fail("attestation user_data does not bind the expected payload"));
    }
    if now_ms.saturating_sub(doc.timestamp_ms) > max_age_ms {
        return Err(fail("attestation document is stale"));
    }
    accepted.check(&doc.pcrs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nitro::{AcceptedMeasurement, MeasurementRegistry};

    #[test]
    fn malformed_documents_are_rejected() {
        assert!(verify_document(&[0x00, 0x01, 0x02]).is_err());
        assert!(verify_document(b"not cbor at all").is_err());
        assert!(verify_document(&[]).is_err());
        // A valid CBOR array of the wrong shape (not COSE_Sign1's 4 byte-strings).
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Array(vec![Value::Integer(1.into())]), &mut buf).unwrap();
        assert!(verify_document(&buf).is_err());
    }

    #[test]
    fn root_fingerprint_is_the_published_aws_value() {
        // Sanity: the pinned fingerprint is exactly AWS's published 32 bytes.
        assert_eq!(AWS_NITRO_ROOT_SHA256_FINGERPRINT.len(), 32);
        assert_eq!(AWS_NITRO_ROOT_SHA256_FINGERPRINT[0], 0x64);
        assert_eq!(AWS_NITRO_ROOT_SHA256_FINGERPRINT[31], 0x5B);
    }

    fn pcrs(p0: u8, p1: u8, p2: u8) -> std::collections::BTreeMap<u32, Vec<u8>> {
        let mut m = std::collections::BTreeMap::new();
        m.insert(0, vec![p0; 48]);
        m.insert(1, vec![p1; 48]);
        m.insert(2, vec![p2; 48]);
        m
    }

    #[test]
    fn registry_accepts_only_registered_measurements() {
        let mut reg = MeasurementRegistry::new();
        assert!(reg.is_empty());
        reg.allow(AcceptedMeasurement {
            pcr0: vec![1; 48],
            pcr1: vec![2; 48],
            pcr2: vec![3; 48],
            pcr8: None,
        });
        assert_eq!(reg.len(), 1);
        assert!(reg.check(&pcrs(1, 2, 3)).is_ok(), "exact match accepted");
        assert!(reg.check(&pcrs(9, 2, 3)).is_err(), "wrong PCR0 rejected");
        assert!(reg.check(&pcrs(1, 9, 3)).is_err(), "wrong PCR1 rejected");
        assert!(reg.check(&std::collections::BTreeMap::new()).is_err(), "empty PCRs rejected");
    }

    #[test]
    fn registry_enforces_pcr8_when_present() {
        let mut reg = MeasurementRegistry::new();
        reg.allow(AcceptedMeasurement {
            pcr0: vec![1; 48],
            pcr1: vec![2; 48],
            pcr2: vec![3; 48],
            pcr8: Some(vec![8; 48]),
        });
        let mut ok = pcrs(1, 2, 3);
        ok.insert(8, vec![8; 48]);
        assert!(reg.check(&ok).is_ok(), "matching PCR8 accepted");
        let mut bad = pcrs(1, 2, 3);
        bad.insert(8, vec![7; 48]);
        assert!(reg.check(&bad).is_err(), "wrong PCR8 rejected");
        assert!(reg.check(&pcrs(1, 2, 3)).is_err(), "missing PCR8 rejected when enforced");
    }

    #[test]
    fn policy_binds_user_data_and_freshness() {
        let mut reg = MeasurementRegistry::new();
        reg.allow(AcceptedMeasurement {
            pcr0: vec![1; 48],
            pcr1: vec![2; 48],
            pcr2: vec![3; 48],
            pcr8: None,
        });
        let doc = VerifiedAttestation {
            pcrs: pcrs(1, 2, 3),
            user_data: b"execution-attestation-body".to_vec(),
            nonce: vec![7; 32],
            timestamp_ms: 1_000_000,
            module_id: "i-abc".to_string(),
        };
        // Correct body + fresh + accepted PCRs.
        assert!(check_policy(&doc, &reg, b"execution-attestation-body", 1_000_500, 10_000).is_ok());
        // Wrong bound body rejected.
        assert!(check_policy(&doc, &reg, b"different-body", 1_000_500, 10_000).is_err());
        // Stale document rejected.
        assert!(check_policy(&doc, &reg, b"execution-attestation-body", 2_000_000, 10_000).is_err());
        // Unaccepted PCRs rejected even with correct body.
        let doc2 = VerifiedAttestation { pcrs: pcrs(9, 9, 9), ..doc.clone() };
        assert!(check_policy(&doc2, &reg, b"execution-attestation-body", 1_000_500, 10_000).is_err());
    }
}
