//! AWS Nitro Enclaves attestation — real verification, pure Rust.
//!
//! An enclave obtains a *Signed Attestation Document* from the Nitro Security
//! Module: a CBOR-encoded `COSE_Sign1` object signed with **ES384** (ECDSA P-384 +
//! SHA-384). This module verifies such a document end to end:
//!
//! 1. parse the `COSE_Sign1` structure and its `AttestationDocument` payload;
//! 2. validate the embedded X.509 certificate chain from the leaf up to the AWS
//!    Nitro root certificate the deployment pins;
//! 3. verify the `COSE_Sign1` signature with the leaf certificate's P-384 key over
//!    the canonical `Sig_structure`;
//! 4. check the PCRs (enclave code measurements) against the expected set;
//! 5. check the bound `user_data` (for AEVOR, the `ExecutionAttestation` body).
//!
//! The root certificate is supplied by the caller: the deployment downloads the
//! AWS-published root (`AWS_NitroEnclaves_Root-G1.zip`) and checks it against
//! [`AWS_NITRO_ROOT_G1_SHA256_FINGERPRINT`] before pinning it. Passing the root as
//! configuration supports partitions and rotation without a rebuild.

use ciborium::value::Value;
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;
use x509_parser::prelude::*;

/// SHA-256 fingerprint of the AWS Nitro Enclaves Root G1 certificate, published by
/// AWS. A deployment verifies its pinned root against this before trusting it.
pub const AWS_NITRO_ROOT_G1_SHA256_FINGERPRINT: [u8; 32] = [
    0x64, 0x1A, 0x03, 0x21, 0xA3, 0xE2, 0x44, 0xEF, 0xE4, 0x56, 0x46, 0x31, 0x95, 0xD6, 0x06, 0x31,
    0x7E, 0xD7, 0xCD, 0xCC, 0x3C, 0x17, 0x56, 0xE0, 0x98, 0x93, 0xF3, 0xC6, 0x8F, 0x79, 0xBB, 0x5B,
];

/// Reasons a Nitro attestation fails verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NitroError {
    /// The bytes are not a well-formed CBOR / `COSE_Sign1` structure.
    Structure(String),
    /// The certificate chain does not validate up to the pinned root.
    CertChain(String),
    /// The `COSE_Sign1` signature did not verify against the leaf key.
    Signature(String),
    /// A PCR did not match the expected code-measurement registry.
    PcrMismatch { index: u32 },
    /// The bound `user_data` did not match the expected value.
    UserDataMismatch,
    /// The pinned root certificate did not match the AWS fingerprint.
    RootFingerprint,
}

impl core::fmt::Display for NitroError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Structure(m) => write!(f, "malformed attestation structure: {m}"),
            Self::CertChain(m) => write!(f, "certificate chain invalid: {m}"),
            Self::Signature(m) => write!(f, "signature verification failed: {m}"),
            Self::PcrMismatch { index } => write!(f, "PCR{index} did not match expected measurement"),
            Self::UserDataMismatch => write!(f, "attestation user_data did not match expected binding"),
            Self::RootFingerprint => write!(f, "pinned root certificate fingerprint mismatch"),
        }
    }
}

impl std::error::Error for NitroError {}

/// A parsed AWS Nitro attestation document (the `COSE_Sign1` payload).
#[derive(Debug, Clone)]
pub struct AttestationDocument {
    /// Issuing Nitro hypervisor module id.
    pub module_id: String,
    /// Creation time, milliseconds since the UNIX epoch.
    pub timestamp: u64,
    /// Digest function used for the register values (e.g. `"SHA384"`).
    pub digest: String,
    /// All locked PCRs at attestation time: index → measurement bytes.
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    /// DER-encoded leaf certificate whose key signed the document.
    pub certificate: Vec<u8>,
    /// DER-encoded CA bundle (root's child … the leaf's issuer), excluding the root.
    pub cabundle: Vec<Vec<u8>>,
    /// Optional DER public key the consumer may encrypt to.
    pub public_key: Option<Vec<u8>>,
    /// Optional application data bound into the attestation (AEVOR: the
    /// `ExecutionAttestation` body).
    pub user_data: Option<Vec<u8>>,
    /// Optional caller nonce (freshness).
    pub nonce: Option<Vec<u8>>,
}

/// The `COSE_Sign1` fields needed to verify the signature.
struct CoseSign1 {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn structure(msg: impl Into<String>) -> NitroError {
    NitroError::Structure(msg.into())
}

/// Parse a (possibly tag-18) `COSE_Sign1` CBOR array into its raw fields.
fn parse_cose_sign1(bytes: &[u8]) -> Result<CoseSign1, NitroError> {
    let value: Value =
        ciborium::de::from_reader(bytes).map_err(|e| structure(format!("cbor: {e}")))?;
    // Unwrap CBOR tag 18 if present.
    let array = match value {
        Value::Tag(18, inner) => *inner,
        other => other,
    };
    let Value::Array(items) = array else {
        return Err(structure("COSE_Sign1 is not a CBOR array"));
    };
    if items.len() != 4 {
        return Err(structure("COSE_Sign1 array must have 4 elements"));
    }
    let protected = as_bytes(&items[0]).ok_or_else(|| structure("protected header not bstr"))?;
    let payload = as_bytes(&items[2]).ok_or_else(|| structure("payload not bstr"))?;
    let signature = as_bytes(&items[3]).ok_or_else(|| structure("signature not bstr"))?;
    Ok(CoseSign1 { protected, payload, signature })
}

fn as_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u128::try_from(*i).ok().and_then(|n| u64::try_from(n).ok()),
        _ => None,
    }
}

/// Parse the CBOR `AttestationDocument` map from the payload bytes.
fn parse_document(payload: &[u8]) -> Result<AttestationDocument, NitroError> {
    let value: Value =
        ciborium::de::from_reader(payload).map_err(|e| structure(format!("doc cbor: {e}")))?;
    let Value::Map(entries) = value else {
        return Err(structure("attestation document is not a map"));
    };
    let get = |key: &str| entries.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key)).map(|(_, v)| v);

    let module_id = match get("module_id") {
        Some(Value::Text(t)) => t.clone(),
        _ => return Err(structure("module_id missing")),
    };
    let timestamp = get("timestamp").and_then(as_u64).ok_or_else(|| structure("timestamp missing"))?;
    let digest = match get("digest") {
        Some(Value::Text(t)) => t.clone(),
        _ => return Err(structure("digest missing")),
    };
    let pcrs = match get("pcrs") {
        Some(Value::Map(m)) => {
            let mut out = BTreeMap::new();
            for (k, v) in m {
                let idx = as_u64(k).ok_or_else(|| structure("pcr index not integer"))?;
                let val = as_bytes(v).ok_or_else(|| structure("pcr value not bstr"))?;
                out.insert(u32::try_from(idx).map_err(|_| structure("pcr index too large"))?, val);
            }
            out
        }
        _ => return Err(structure("pcrs missing")),
    };
    let certificate = get("certificate").and_then(as_bytes).ok_or_else(|| structure("certificate missing"))?;
    let cabundle = match get("cabundle") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| as_bytes(v).ok_or_else(|| structure("cabundle entry not bstr")))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(structure("cabundle missing")),
    };
    let public_key = get("public_key").and_then(as_bytes);
    let user_data = get("user_data").and_then(as_bytes);
    let nonce = get("nonce").and_then(as_bytes);

    Ok(AttestationDocument {
        module_id,
        timestamp,
        digest,
        pcrs,
        certificate,
        cabundle,
        public_key,
        user_data,
        nonce,
    })
}

/// The canonical `Sig_structure` bytes for a `COSE_Sign1` signature (RFC 8152
/// §4.4): `["Signature1", protected, external_aad (empty), payload]`, CBOR-encoded.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, NitroError> {
    let sig_struct = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&sig_struct, &mut out)
        .map_err(|e| structure(format!("sig_structure encode: {e}")))?;
    Ok(out)
}

/// Verify a certificate's signature against its issuer's public key.
fn verify_cert_signed_by(child_der: &[u8], issuer_der: &[u8]) -> Result<(), NitroError> {
    let (_, issuer) =
        X509Certificate::from_der(issuer_der).map_err(|e| NitroError::CertChain(format!("issuer parse: {e}")))?;
    let (_, child) =
        X509Certificate::from_der(child_der).map_err(|e| NitroError::CertChain(format!("child parse: {e}")))?;
    child
        .verify_signature(Some(issuer.public_key()))
        .map_err(|e| NitroError::CertChain(format!("chain link: {e}")))
}

/// Verify the full chain: root → cabundle[0] → … → cabundle[n-1] → leaf, and that
/// the root matches `pinned_root_der`.
fn verify_chain(doc: &AttestationDocument, pinned_root_der: &[u8]) -> Result<(), NitroError> {
    // The document's cabundle starts at the AWS root's direct child. The pinned
    // root is the trust anchor; the document must chain to it.
    let mut prev = pinned_root_der;
    for ca in &doc.cabundle {
        verify_cert_signed_by(ca, prev)?;
        prev = ca;
    }
    // Finally the leaf certificate is signed by the last CA in the bundle (or the
    // root itself if the bundle is empty).
    verify_cert_signed_by(&doc.certificate, prev)?;
    Ok(())
}

/// Verify the `COSE_Sign1` ES384 signature with the leaf certificate's P-384 key.
fn verify_cose_signature(cose: &CoseSign1, leaf_der: &[u8]) -> Result<(), NitroError> {
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    let (_, leaf) =
        X509Certificate::from_der(leaf_der).map_err(|e| NitroError::Signature(format!("leaf parse: {e}")))?;
    // SEC1-encoded EC point from the certificate's SubjectPublicKeyInfo.
    let spki_point = leaf.public_key().subject_public_key.data.as_ref();
    let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(spki_point)
        .map_err(|e| NitroError::Signature(format!("leaf key: {e}")))?;
    // COSE signature is the fixed-size concatenation r‖s (48+48 bytes for P-384).
    let signature = p384::ecdsa::Signature::from_slice(&cose.signature)
        .map_err(|e| NitroError::Signature(format!("sig decode: {e}")))?;
    // ES384 = ECDSA P-384 over SHA-384(Sig_structure).
    let to_sign = sig_structure(&cose.protected, &cose.payload)?;
    let prehash = Sha384::digest(&to_sign);
    verifying_key
        .verify_prehash(&prehash, &signature)
        .map_err(|e| NitroError::Signature(format!("verify: {e}")))
}

/// SHA-256 fingerprint of a DER certificate (for pinning the root).
#[must_use]
pub fn cert_fingerprint_sha256(cert_der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cert_der);
    h.finalize().into()
}

/// Confirm a DER root certificate matches the AWS Nitro Root G1 fingerprint.
///
/// # Errors
/// [`NitroError::RootFingerprint`] if the fingerprint does not match.
pub fn check_root_fingerprint(root_der: &[u8]) -> Result<(), NitroError> {
    if cert_fingerprint_sha256(root_der) == AWS_NITRO_ROOT_G1_SHA256_FINGERPRINT {
        Ok(())
    } else {
        Err(NitroError::RootFingerprint)
    }
}

/// What a verifier requires of an attestation, agreed by the network.
pub struct ExpectedAttestation<'a> {
    /// The pinned AWS Nitro root certificate (DER). The deployment loads the
    /// AWS-published root and should first pass it through [`check_root_fingerprint`].
    pub root_der: &'a [u8],
    /// The accepted code-measurement registry: PCR index → expected value. Every
    /// listed PCR must match. (Typically PCR0, and PCR1/PCR2 where pinned.)
    pub expected_pcrs: &'a BTreeMap<u32, Vec<u8>>,
    /// The exact `user_data` the attestation must carry (AEVOR: the
    /// `ExecutionAttestation` body). `None` skips the binding check.
    pub expected_user_data: Option<&'a [u8]>,
}

/// Verify an AWS Nitro Enclaves attestation document end to end and return the
/// parsed, trusted document on success.
///
/// Steps: parse `COSE_Sign1` and payload → validate the X.509 chain to the pinned
/// root → verify the ES384 signature with the leaf key → check every expected PCR
/// → check the bound `user_data`. All checks must pass.
///
/// # Errors
/// Returns the first [`NitroError`] encountered (structure, chain, signature, PCR,
/// or `user_data` mismatch).
pub fn verify(cose_bytes: &[u8], expected: &ExpectedAttestation<'_>) -> Result<AttestationDocument, NitroError> {
    let cose = parse_cose_sign1(cose_bytes)?;
    let doc = parse_document(&cose.payload)?;

    // 1. Certificate chain to the pinned AWS root.
    verify_chain(&doc, expected.root_der)?;
    // 2. COSE signature with the (now-trusted) leaf key.
    verify_cose_signature(&cose, &doc.certificate)?;
    // 3. Code-measurement registry: every expected PCR must match.
    for (index, want) in expected.expected_pcrs {
        match doc.pcrs.get(index) {
            Some(got) if got == want => {}
            _ => return Err(NitroError::PcrMismatch { index: *index }),
        }
    }
    // 4. Bound application data (the AEVOR ExecutionAttestation body).
    if let Some(want) = expected.expected_user_data {
        if doc.user_data.as_deref() != Some(want) {
            return Err(NitroError::UserDataMismatch);
        }
    }
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_constant_and_helper_agree_on_shape() {
        // A known-size sanity check plus the round-trip of the fingerprint helper on
        // arbitrary bytes (real Nitro documents are exercised on hardware).
        let fp = cert_fingerprint_sha256(b"not-a-real-cert");
        assert_eq!(fp.len(), 32);
        assert_ne!(fp, AWS_NITRO_ROOT_G1_SHA256_FINGERPRINT);
        assert!(check_root_fingerprint(b"wrong").is_err());
    }

    #[test]
    fn malformed_cose_is_rejected_not_panicked() {
        let expected_pcrs = BTreeMap::new();
        let expected = ExpectedAttestation {
            root_der: b"root",
            expected_pcrs: &expected_pcrs,
            expected_user_data: None,
        };
        assert!(matches!(verify(&[0x00, 0x01, 0x02], &expected), Err(NitroError::Structure(_))));
    }

    #[test]
    fn sig_structure_is_deterministic_cbor() {
        let a = sig_structure(b"prot", b"payload").unwrap();
        let b = sig_structure(b"prot", b"payload").unwrap();
        assert_eq!(a, b);
        // Starts with a 4-element array header (0x84).
        assert_eq!(a[0], 0x84);
    }
}
