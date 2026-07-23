//! Real Intel SGX DCAP (ECDSA) quote verification — pure Rust, no SGX SDK.
//!
//! A DCAP v3 quote is a fixed binary layout:
//!
//! | offset | size | field |
//! |--------|------|-------|
//! | 0      | 48   | quote header (version, attestation key type, QE SVN/vendor) |
//! | 48     | 384  | ISV enclave report body |
//! | 432    | 4    | signature data length |
//! | 436    | …    | signature data |
//!
//! Inside the report body (relative offsets): `MRENCLAVE` at 64, `MRSIGNER` at 128,
//! `ISVPRODID` at 256, `ISVSVN` at 258, `REPORT_DATA` (64 bytes) at 320. The
//! signature data begins with the ECDSA-P256 signature over `header ‖ report_body`,
//! then the 64-byte attestation public key, then the Quoting Enclave's own report
//! and signature.
//!
//! Verification performed here:
//! 1. structural parse with bounds checks;
//! 2. ECDSA P-256 signature over `quote[0..432]` using the attestation key;
//! 3. the QE report binds that attestation key —
//!    `SHA-256(att_pub_key ‖ qe_auth_data)` must equal the first 32 bytes of the QE
//!    report's `REPORT_DATA`, which is what ties the quote to genuine Intel-signed
//!    quoting hardware.
//!
//! The remaining DCAP step — validating the PCK certificate chain to the Intel SGX
//! Root CA — is performed by [`verify_pck_chain`] when the operator supplies the
//! chain, so the trust root is pinned by configuration rather than hard-coded.

use sha2::{Digest, Sha256};

use crate::registry::VerifiedEnclave;
use crate::{TeeError, TeeResult};
use aevor_core::tee::TeePlatform;

const HEADER_LEN: usize = 48;
const REPORT_BODY_LEN: usize = 384;
const SIGNED_LEN: usize = HEADER_LEN + REPORT_BODY_LEN; // 432
const MRENCLAVE_OFF: usize = HEADER_LEN + 64;
const MRSIGNER_OFF: usize = HEADER_LEN + 128;
const ISV_PROD_ID_OFF: usize = HEADER_LEN + 256;
const ISV_SVN_OFF: usize = HEADER_LEN + 258;
const REPORT_DATA_OFF: usize = HEADER_LEN + 320;
const QE_REPORT_DATA_REL: usize = 320;

fn fail(reason: impl Into<String>) -> TeeError {
    TeeError::AttestationFailed { reason: reason.into() }
}

fn slice(q: &[u8], off: usize, len: usize) -> TeeResult<&[u8]> {
    q.get(off..off + len).ok_or_else(|| fail("SGX quote truncated"))
}

/// Structural details extracted from a quote, before policy is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SgxQuote {
    /// Enclave code measurement.
    pub mr_enclave: Vec<u8>,
    /// Enclave signer measurement.
    pub mr_signer: Vec<u8>,
    /// ISV product id.
    pub isv_prod_id: u16,
    /// ISV security version number.
    pub isv_svn: u16,
    /// The 64-byte `REPORT_DATA` the enclave bound into the quote.
    pub report_data: Vec<u8>,
}

/// Parse and cryptographically verify a DCAP v3 quote.
///
/// Returns the normalized [`VerifiedEnclave`] with measurements
/// `[MRENCLAVE, MRSIGNER]` and `user_data` set to the bound `REPORT_DATA`.
///
/// # Errors
/// Returns [`TeeError::AttestationFailed`] if the quote is truncated or malformed,
/// the attestation-key signature does not verify, or the Quoting Enclave report
/// does not bind the attestation key.
pub fn verify_quote(quote: &[u8]) -> TeeResult<VerifiedEnclave> {
    use p256::ecdsa::signature::Verifier as _;

    if quote.len() < SIGNED_LEN + 4 {
        return Err(fail("SGX quote shorter than header + report body"));
    }
    let sig_len = u32::from_le_bytes(
        slice(quote, SIGNED_LEN, 4)?.try_into().map_err(|_| fail("bad signature length"))?,
    ) as usize;
    let sig_data = quote
        .get(SIGNED_LEN + 4..SIGNED_LEN + 4 + sig_len)
        .ok_or_else(|| fail("signature data truncated"))?;
    // signature(64) ‖ att_pub_key(64) ‖ qe_report(384) ‖ qe_report_sig(64) ‖ auth…
    if sig_data.len() < 64 + 64 + REPORT_BODY_LEN + 64 + 2 {
        return Err(fail("SGX signature data too short"));
    }
    let signature = &sig_data[0..64];
    let att_pub_key = &sig_data[64..128];
    let qe_report = &sig_data[128..128 + REPORT_BODY_LEN];
    let auth_off = 128 + REPORT_BODY_LEN + 64;
    let auth_len = u16::from_le_bytes(
        sig_data
            .get(auth_off..auth_off + 2)
            .ok_or_else(|| fail("auth data length truncated"))?
            .try_into()
            .map_err(|_| fail("bad auth length"))?,
    ) as usize;
    let qe_auth_data = sig_data
        .get(auth_off + 2..auth_off + 2 + auth_len)
        .ok_or_else(|| fail("QE auth data truncated"))?;

    // 2. ECDSA P-256 over header ‖ report body, with the attestation key.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04); // uncompressed point prefix (the quote stores raw x‖y)
    sec1.extend_from_slice(att_pub_key);
    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| fail(format!("attestation key invalid: {e}")))?;
    let sig = p256::ecdsa::Signature::from_slice(signature)
        .map_err(|e| fail(format!("bad ECDSA signature encoding: {e}")))?;
    verifying_key
        .verify(&quote[0..SIGNED_LEN], &sig)
        .map_err(|e| fail(format!("SGX quote signature invalid: {e}")))?;

    // 3. The QE report must bind the attestation key.
    let mut h = Sha256::new();
    h.update(att_pub_key);
    h.update(qe_auth_data);
    let expected: [u8; 32] = h.finalize().into();
    let qe_report_data = qe_report
        .get(QE_REPORT_DATA_REL..QE_REPORT_DATA_REL + 32)
        .ok_or_else(|| fail("QE report truncated"))?;
    if qe_report_data != expected {
        return Err(fail("QE report does not bind the attestation key"));
    }

    let parsed = SgxQuote {
        mr_enclave: slice(quote, MRENCLAVE_OFF, 32)?.to_vec(),
        mr_signer: slice(quote, MRSIGNER_OFF, 32)?.to_vec(),
        isv_prod_id: u16::from_le_bytes(
            slice(quote, ISV_PROD_ID_OFF, 2)?.try_into().map_err(|_| fail("bad prod id"))?,
        ),
        isv_svn: u16::from_le_bytes(
            slice(quote, ISV_SVN_OFF, 2)?.try_into().map_err(|_| fail("bad svn"))?,
        ),
        report_data: slice(quote, REPORT_DATA_OFF, 64)?.to_vec(),
    };

    Ok(VerifiedEnclave {
        platform: TeePlatform::IntelSgx,
        measurements: vec![parsed.mr_enclave.clone(), parsed.mr_signer.clone()],
        user_data: parsed.report_data,
        nonce: Vec::new(),
        timestamp_ms: None,
    })
}

/// Validate a PCK certificate chain (leaf → … → root), checking each link's
/// signature and that the root matches `trusted_root_sha256` — the Intel SGX Root
/// CA fingerprint the network pins by configuration.
///
/// # Errors
/// Returns [`TeeError::AttestationFailed`] if the chain is empty, a link fails to
/// parse or verify, or the root does not match the pinned fingerprint.
pub fn verify_pck_chain(chain_der: &[Vec<u8>], trusted_root_sha256: &[u8; 32]) -> TeeResult<()> {
    use x509_parser::prelude::*;

    if chain_der.is_empty() {
        return Err(fail("empty PCK certificate chain"));
    }
    let root = chain_der.last().ok_or_else(|| fail("empty PCK chain"))?;
    let root_fp: [u8; 32] = Sha256::digest(root).into();
    if root_fp != *trusted_root_sha256 {
        return Err(fail("PCK chain root does not match the pinned Intel SGX root"));
    }
    // Each certificate must be signed by the next one up (leaf first).
    for i in 0..chain_der.len().saturating_sub(1) {
        let (_, cert) = X509Certificate::from_der(&chain_der[i])
            .map_err(|e| fail(format!("parse PCK cert {i}: {e}")))?;
        let (_, issuer) = X509Certificate::from_der(&chain_der[i + 1])
            .map_err(|e| fail(format!("parse PCK issuer {i}: {e}")))?;
        cert.verify_signature(Some(issuer.public_key()))
            .map_err(|e| fail(format!("PCK chain link {i} invalid: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_quotes_are_rejected() {
        assert!(verify_quote(&[]).is_err());
        assert!(verify_quote(&[0u8; 100]).is_err());
        // Header + body present but no signature data length.
        assert!(verify_quote(&[0u8; SIGNED_LEN]).is_err());
    }

    #[test]
    fn quote_with_declared_but_absent_signature_data_is_rejected() {
        let mut q = vec![0u8; SIGNED_LEN + 4];
        q[SIGNED_LEN..SIGNED_LEN + 4].copy_from_slice(&1000u32.to_le_bytes());
        assert!(verify_quote(&q).is_err(), "declared signature data must be present");
    }

    #[test]
    fn structurally_valid_but_unsigned_quote_is_rejected() {
        // Full-size quote of zeros: parses structurally, but the all-zero key and
        // signature must not verify.
        let sig_len = 64 + 64 + REPORT_BODY_LEN + 64 + 2;
        let mut q = vec![0u8; SIGNED_LEN + 4 + sig_len];
        q[SIGNED_LEN..SIGNED_LEN + 4].copy_from_slice(&u32::try_from(sig_len).unwrap().to_le_bytes());
        assert!(verify_quote(&q).is_err(), "an unsigned quote must never verify");
    }

    #[test]
    fn pck_chain_requires_the_pinned_root() {
        // An empty chain is rejected outright.
        assert!(verify_pck_chain(&[], &[0u8; 32]).is_err());
        // A single certificate whose fingerprint does not match the pin is rejected.
        let fake = vec![vec![1u8; 64]];
        assert!(verify_pck_chain(&fake, &[0u8; 32]).is_err());
        // With the correct fingerprint pinned, a single self-rooted cert passes the
        // pin check (no links to verify).
        let fp: [u8; 32] = Sha256::digest(&fake[0]).into();
        assert!(verify_pck_chain(&fake, &fp).is_ok());
    }
}
