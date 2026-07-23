//! Real AMD SEV-SNP attestation report verification — pure Rust.
//!
//! An SNP attestation report is a fixed 1184-byte structure. The fields this
//! verifier depends on (absolute offsets, little-endian):
//!
//! | offset | size | field |
//! |--------|------|-------|
//! | 0      | 4    | version |
//! | 4      | 4    | guest SVN |
//! | 8      | 8    | policy |
//! | 48     | 4    | VMPL |
//! | 80     | 64   | `REPORT_DATA` (guest-supplied binding) |
//! | 144    | 48   | `MEASUREMENT` (launch measurement of the guest image) |
//! | 192    | 32   | host data |
//! | 384    | 8    | reported TCB |
//! | 416    | 64   | chip id |
//! | 672    | 512  | signature (ECDSA P-384, r ‖ s little-endian, zero-padded) |
//!
//! The signature covers bytes `[0, 672)` and is made by the VCEK — the
//! chip-and-TCB-specific key whose certificate is issued by AMD's Key Distribution
//! Service. The operator supplies the VCEK certificate (DER); this verifier checks
//! the report signature against the key in that certificate.

use crate::registry::VerifiedEnclave;
use crate::{TeeError, TeeResult};
use aevor_core::tee::TeePlatform;

/// Total size of an SEV-SNP attestation report.
pub const REPORT_LEN: usize = 1184;
/// The report region covered by the signature.
pub const SIGNED_LEN: usize = 672;
const REPORT_DATA_OFF: usize = 80;
const MEASUREMENT_OFF: usize = 144;
const HOST_DATA_OFF: usize = 192;
const CHIP_ID_OFF: usize = 416;
const SIG_OFF: usize = 672;
/// P-384 component width inside the 512-byte signature field.
const SIG_COMPONENT_LEN: usize = 72;

fn fail(reason: impl Into<String>) -> TeeError {
    TeeError::AttestationFailed { reason: reason.into() }
}

/// Fields parsed out of an SNP report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnpReport {
    /// Report format version.
    pub version: u32,
    /// Guest security version number.
    pub guest_svn: u32,
    /// Guest policy bits.
    pub policy: u64,
    /// Launch measurement of the guest image (48 bytes).
    pub measurement: Vec<u8>,
    /// Guest-supplied 64-byte binding data.
    pub report_data: Vec<u8>,
    /// Host-supplied data (32 bytes).
    pub host_data: Vec<u8>,
    /// Chip identifier (64 bytes).
    pub chip_id: Vec<u8>,
}

/// Parse an SNP report without verifying its signature. Useful for inspection;
/// consensus paths must use [`verify_report`].
///
/// # Errors
/// Returns [`TeeError::AttestationFailed`] if the report is not [`REPORT_LEN`] bytes.
pub fn parse_report(report: &[u8]) -> TeeResult<SnpReport> {
    if report.len() < REPORT_LEN {
        return Err(fail("SEV-SNP report shorter than 1184 bytes"));
    }
    let u32_at = |o: usize| -> u32 {
        u32::from_le_bytes([report[o], report[o + 1], report[o + 2], report[o + 3]])
    };
    let u64_at = |o: usize| -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&report[o..o + 8]);
        u64::from_le_bytes(b)
    };
    Ok(SnpReport {
        version: u32_at(0),
        guest_svn: u32_at(4),
        policy: u64_at(8),
        measurement: report[MEASUREMENT_OFF..MEASUREMENT_OFF + 48].to_vec(),
        report_data: report[REPORT_DATA_OFF..REPORT_DATA_OFF + 64].to_vec(),
        host_data: report[HOST_DATA_OFF..HOST_DATA_OFF + 32].to_vec(),
        chip_id: report[CHIP_ID_OFF..CHIP_ID_OFF + 64].to_vec(),
    })
}

/// Verify an SNP report's signature against the VCEK certificate (DER) issued by
/// AMD's Key Distribution Service, and return the normalized enclave identity with
/// measurement `[MEASUREMENT]` and `user_data` set to `REPORT_DATA`.
///
/// # Errors
/// Returns [`TeeError::AttestationFailed`] if the report is malformed, the VCEK
/// certificate cannot be parsed as P-384, or the signature does not verify.
pub fn verify_report(report: &[u8], vcek_der: &[u8]) -> TeeResult<VerifiedEnclave> {
    use p384::ecdsa::signature::Verifier as _;
    use x509_parser::prelude::*;

    let parsed = parse_report(report)?;

    // The signature field stores r and s as little-endian, zero-padded to 72 bytes.
    let sig_field = report
        .get(SIG_OFF..SIG_OFF + 2 * SIG_COMPONENT_LEN)
        .ok_or_else(|| fail("SNP signature field truncated"))?;
    let mut r = sig_field[0..SIG_COMPONENT_LEN].to_vec();
    let mut s = sig_field[SIG_COMPONENT_LEN..2 * SIG_COMPONENT_LEN].to_vec();
    r.reverse(); // → big-endian
    s.reverse();
    // P-384 components are 48 bytes; the field is zero-padded above that.
    if r[..SIG_COMPONENT_LEN - 48].iter().any(|b| *b != 0)
        || s[..SIG_COMPONENT_LEN - 48].iter().any(|b| *b != 0)
    {
        return Err(fail("SNP signature components exceed P-384 width"));
    }
    let mut raw = Vec::with_capacity(96);
    raw.extend_from_slice(&r[SIG_COMPONENT_LEN - 48..]);
    raw.extend_from_slice(&s[SIG_COMPONENT_LEN - 48..]);
    let sig = p384::ecdsa::Signature::from_slice(&raw)
        .map_err(|e| fail(format!("bad SNP signature encoding: {e}")))?;

    let (_, cert) =
        X509Certificate::from_der(vcek_der).map_err(|e| fail(format!("parse VCEK: {e}")))?;
    let point = cert.public_key().subject_public_key.data.as_ref();
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
        .map_err(|e| fail(format!("VCEK key is not P-384: {e}")))?;

    key.verify(&report[0..SIGNED_LEN], &sig)
        .map_err(|e| fail(format!("SNP report signature invalid: {e}")))?;

    Ok(VerifiedEnclave {
        platform: TeePlatform::AmdSev,
        measurements: vec![parsed.measurement],
        user_data: parsed.report_data,
        nonce: Vec::new(),
        timestamp_ms: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_reports_are_rejected() {
        assert!(parse_report(&[]).is_err());
        assert!(parse_report(&[0u8; 100]).is_err());
        assert!(verify_report(&[0u8; 100], &[0u8; 10]).is_err());
    }

    #[test]
    fn parses_measurement_and_report_data_at_the_right_offsets() {
        let mut r = vec![0u8; REPORT_LEN];
        r[0..4].copy_from_slice(&2u32.to_le_bytes()); // version
        r[REPORT_DATA_OFF..REPORT_DATA_OFF + 64].copy_from_slice(&[0xAB; 64]);
        r[MEASUREMENT_OFF..MEASUREMENT_OFF + 48].copy_from_slice(&[0xCD; 48]);
        let p = parse_report(&r).unwrap();
        assert_eq!(p.version, 2);
        assert_eq!(p.report_data, vec![0xAB; 64]);
        assert_eq!(p.measurement, vec![0xCD; 48]);
        assert_eq!(p.measurement.len(), 48, "SNP measurement is 48 bytes");
    }

    #[test]
    fn unsigned_report_never_verifies() {
        let r = vec![0u8; REPORT_LEN];
        // No valid VCEK, and an all-zero signature: must fail.
        assert!(verify_report(&r, &[0u8; 64]).is_err());
    }

    #[test]
    fn oversized_signature_components_are_rejected() {
        let mut r = vec![0u8; REPORT_LEN];
        // Set a byte in the zero-padding region of r (little-endian high bytes).
        r[SIG_OFF + 71] = 0x01;
        assert!(verify_report(&r, &[0u8; 64]).is_err());
    }
}
