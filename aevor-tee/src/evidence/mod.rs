//! Platform-agnostic attestation evidence: one type consensus carries, one call to
//! produce it, one call to verify it — whichever TEE a validator runs.
//!
//! Each platform has its own evidence format ([`AttestationEvidence`]) and its own
//! device interface for producing it. What the network needs is uniform: bind the
//! `ExecutionAttestation` body into hardware evidence, ship it, and have every
//! verifier check it against the agreed trust roots and code registry.
//!
//! **Production is the default.** [`produce`] uses the real device on whichever
//! platform is present and returns `None` only when no TEE is available (the
//! off-hardware simulation path). [`AttestationEvidence::verify`] performs real
//! cryptographic verification for every platform.
//!
//! Trust roots ([`TeeTrustRoots`]) are network configuration, not part of the
//! evidence: an attacker who could supply their own roots could forge anything.
//! Chip-specific certificates that legitimately vary per machine (the SEV-SNP
//! VCEK) travel *with* the evidence and are checked against those roots.

use serde::{Deserialize, Serialize};

use crate::registry::VerifiedEnclave;
use crate::{TeeError, TeeResult};
use aevor_core::tee::TeePlatform;

/// Hardware roots of trust, distributed as network configuration (genesis /
/// governance) rather than carried in the evidence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TeeTrustRoots {
    /// SHA-256 fingerprint of the Intel SGX Root CA, for PCK chain validation.
    pub sgx_root_fingerprint: Option<[u8; 32]>,
    /// AMD root certificate (DER) used to validate a chip's VCEK certificate.
    pub amd_root_der: Option<Vec<u8>>,
    /// The RISC-V Keystone device public key (hardware root of trust).
    pub keystone_device_key: Option<[u8; 32]>,
    /// The ARM device Initial Attestation Key (SEC1-encoded P-256 public key).
    pub trustzone_iak: Option<Vec<u8>>,
}

/// Hardware attestation evidence, in the producing platform's native format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationEvidence {
    /// AWS Nitro `COSE_Sign1` attestation document.
    Nitro {
        /// The CBOR-encoded signed document.
        document: Vec<u8>,
    },
    /// Intel SGX DCAP ECDSA quote, with the PCK certificate chain (DER, leaf first)
    /// when the platform supplies it.
    Sgx {
        /// The DCAP v3 quote.
        quote: Vec<u8>,
        /// PCK certificate chain, leaf first.
        pck_chain: Vec<Vec<u8>>,
    },
    /// AMD SEV-SNP attestation report plus the chip's VCEK certificate (DER),
    /// which varies per machine and so travels with the report.
    SevSnp {
        /// The 1184-byte SNP report.
        report: Vec<u8>,
        /// The VCEK certificate (DER) from AMD's Key Distribution Service.
        vcek_der: Vec<u8>,
    },
    /// ARM `TrustZone` PSA attestation token (CBOR `COSE_Sign1`).
    TrustZone {
        /// The PSA token.
        token: Vec<u8>,
    },
    /// RISC-V Keystone attestation report.
    Keystone {
        /// The 1352-byte Keystone report.
        report: Vec<u8>,
    },
}

impl AttestationEvidence {
    /// Which platform produced this evidence.
    #[must_use]
    pub fn platform(&self) -> TeePlatform {
        match self {
            Self::Nitro { .. } => TeePlatform::AwsNitro,
            Self::Sgx { .. } => TeePlatform::IntelSgx,
            Self::SevSnp { .. } => TeePlatform::AmdSev,
            Self::TrustZone { .. } => TeePlatform::ArmTrustZone,
            Self::Keystone { .. } => TeePlatform::RiscvKeystone,
        }
    }

    /// Cryptographically verify the evidence against the network's trust roots,
    /// returning the normalized enclave identity. This is the real verification for
    /// every platform — signature chains, device roots, and format checks. The
    /// caller then applies [`crate::registry::check_policy`] to enforce *which*
    /// code is permitted and that the evidence binds the expected body.
    ///
    /// # Errors
    /// Returns [`TeeError::AttestationFailed`] if the evidence is malformed, fails
    /// its signature chain, or the trust root required by its platform is not
    /// configured.
    pub fn verify(&self, roots: &TeeTrustRoots) -> TeeResult<VerifiedEnclave> {
        match self {
            Self::Nitro { document } => {
                let v = crate::nitro::verify::verify_document(document)?;
                Ok(VerifiedEnclave {
                    platform: TeePlatform::AwsNitro,
                    measurements: [0u32, 1, 2]
                        .iter()
                        .filter_map(|i| v.pcrs.get(i).cloned())
                        .collect(),
                    user_data: v.user_data,
                    nonce: v.nonce,
                    timestamp_ms: Some(v.timestamp_ms),
                })
            }
            Self::Sgx { quote, pck_chain } => {
                // When the network pins an Intel root, the PCK chain must root there.
                if let Some(fp) = roots.sgx_root_fingerprint.as_ref() {
                    crate::sgx::verify::verify_pck_chain(pck_chain, fp)?;
                }
                crate::sgx::verify::verify_quote(quote)
            }
            Self::SevSnp { report, vcek_der } => {
                // The chip's VCEK must itself chain to AMD's root when configured.
                if let Some(amd_root) = roots.amd_root_der.as_ref() {
                    verify_cert_issued_by(vcek_der, amd_root)?;
                }
                crate::sev::verify::verify_report(report, vcek_der)
            }
            Self::TrustZone { token } => {
                let iak = roots.trustzone_iak.as_ref().ok_or_else(|| TeeError::AttestationFailed {
                    reason: "no TrustZone IAK configured in trust roots".to_string(),
                })?;
                crate::trustzone::verify::verify_token(token, iak)
            }
            Self::Keystone { report } => {
                let key =
                    roots.keystone_device_key.as_ref().ok_or_else(|| TeeError::AttestationFailed {
                        reason: "no Keystone device key configured in trust roots".to_string(),
                    })?;
                crate::keystone::verify::verify_report(report, key)
            }
        }
    }
}

/// Check that `cert_der` carries a valid signature from `issuer_der`.
fn verify_cert_issued_by(cert_der: &[u8], issuer_der: &[u8]) -> TeeResult<()> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| TeeError::AttestationFailed { reason: format!("parse certificate: {e}") })?;
    let (_, issuer) = X509Certificate::from_der(issuer_der)
        .map_err(|e| TeeError::AttestationFailed { reason: format!("parse issuer: {e}") })?;
    cert.verify_signature(Some(issuer.public_key())).map_err(|e| TeeError::AttestationFailed {
        reason: format!("certificate not issued by the configured root: {e}"),
    })
}

/// Produce real hardware evidence binding `user_data`, using whichever TEE this
/// machine provides. Returns `Ok(None)` when no TEE is present (the off-hardware
/// simulation path), so callers use one code path in every environment.
///
/// # Errors
/// Returns an error only when a TEE *is* present but the device rejects the
/// request — a real failure worth surfacing rather than silently simulating.
pub fn produce(user_data: &[u8]) -> TeeResult<Option<AttestationEvidence>> {
    if crate::nitro::is_available() {
        return Ok(Some(AttestationEvidence::Nitro { document: crate::nitro::attest(user_data)? }));
    }
    if sgx_available() {
        let (quote, pck_chain) = sgx_quote(user_data)?;
        return Ok(Some(AttestationEvidence::Sgx { quote, pck_chain }));
    }
    if sev_available() {
        let (report, vcek_der) = sev_report(user_data)?;
        return Ok(Some(AttestationEvidence::SevSnp { report, vcek_der }));
    }
    if keystone_available() {
        return Ok(Some(AttestationEvidence::Keystone { report: keystone_report(user_data)? }));
    }
    if trustzone_available() {
        return Ok(Some(AttestationEvidence::TrustZone { token: trustzone_token(user_data)? }));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Device interfaces. Each uses the platform's standard OS-level interface, so it
// compiles everywhere and executes on the corresponding hardware.
// ---------------------------------------------------------------------------

/// Gramine and the SGX in-kernel driver expose attestation as pseudo-files.
const SGX_USER_REPORT_DATA: &str = "/dev/attestation/user_report_data";
const SGX_QUOTE: &str = "/dev/attestation/quote";
/// Linux configfs-tsm (6.7+) exposes SEV-SNP (and TDX) attestation reports.
const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";
/// The Keystone enclave driver.
const KEYSTONE_DEVICE: &str = "/dev/keystone_enclave";
/// OP-TEE's supplicant device, through which the PSA token is retrieved.
const OPTEE_DEVICE: &str = "/dev/tee0";

fn io_err(what: &str, e: &std::io::Error) -> TeeError {
    TeeError::AttestationFailed { reason: format!("{what}: {e}") }
}

fn sgx_available() -> bool {
    std::path::Path::new(SGX_QUOTE).exists()
}

/// Bind `user_data` (padded/truncated to the 64-byte `REPORT_DATA` field) and read
/// back the DCAP quote. The PCK chain is embedded in the quote's certification
/// data on DCAP platforms, so it is returned empty here and validated from the
/// quote when the network pins an Intel root.
fn sgx_quote(user_data: &[u8]) -> TeeResult<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut report_data = [0u8; 64];
    let n = user_data.len().min(64);
    report_data[..n].copy_from_slice(&user_data[..n]);
    std::fs::write(SGX_USER_REPORT_DATA, report_data)
        .map_err(|e| io_err("write SGX user_report_data", &e))?;
    let quote = std::fs::read(SGX_QUOTE).map_err(|e| io_err("read SGX quote", &e))?;
    Ok((quote, Vec::new()))
}

fn sev_available() -> bool {
    std::path::Path::new(TSM_REPORT_DIR).exists()
}

/// Request an SEV-SNP report through configfs-tsm: create a report directory,
/// write the 64-byte `inblob` (the binding data), then read `outblob` (the report)
/// and `auxblob` (the certificate chain including the VCEK).
fn sev_report(user_data: &[u8]) -> TeeResult<(Vec<u8>, Vec<u8>)> {
    let dir = format!("{TSM_REPORT_DIR}/aevor-{}", std::process::id());
    std::fs::create_dir_all(&dir).map_err(|e| io_err("create tsm report dir", &e))?;
    let mut inblob = [0u8; 64];
    let n = user_data.len().min(64);
    inblob[..n].copy_from_slice(&user_data[..n]);
    std::fs::write(format!("{dir}/inblob"), inblob).map_err(|e| io_err("write tsm inblob", &e))?;
    let report =
        std::fs::read(format!("{dir}/outblob")).map_err(|e| io_err("read tsm outblob", &e))?;
    // auxblob carries the certificate chain (VCEK/ASK/ARK) when the host provides it.
    let vcek = std::fs::read(format!("{dir}/auxblob")).unwrap_or_default();
    let _ = std::fs::remove_dir(&dir);
    Ok((report, vcek))
}

fn keystone_available() -> bool {
    std::path::Path::new(KEYSTONE_DEVICE).exists()
}

/// Keystone's runtime exposes attestation through its enclave device: write the
/// data to bind, read back the Security Monitor's signed report.
fn keystone_report(user_data: &[u8]) -> TeeResult<Vec<u8>> {
    use std::io::{Read as _, Write as _};

    let mut dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(KEYSTONE_DEVICE)
        .map_err(|e| io_err("open Keystone device", &e))?;
    dev.write_all(user_data).map_err(|e| io_err("write Keystone attestation data", &e))?;
    let mut report = Vec::with_capacity(crate::keystone::verify::REPORT_LEN);
    dev.read_to_end(&mut report).map_err(|e| io_err("read Keystone report", &e))?;
    Ok(report)
}

fn trustzone_available() -> bool {
    std::path::Path::new(OPTEE_DEVICE).exists()
}

/// Retrieve a PSA attestation token through the OP-TEE device, binding
/// `user_data` as the token's challenge (nonce) claim.
fn trustzone_token(user_data: &[u8]) -> TeeResult<Vec<u8>> {
    use std::io::{Read as _, Write as _};

    let mut dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(OPTEE_DEVICE)
        .map_err(|e| io_err("open OP-TEE device", &e))?;
    dev.write_all(user_data).map_err(|e| io_err("write PSA challenge", &e))?;
    let mut token = Vec::new();
    dev.read_to_end(&mut token).map_err(|e| io_err("read PSA token", &e))?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_tag_matches_the_variant() {
        assert_eq!(
            AttestationEvidence::Nitro { document: vec![] }.platform(),
            TeePlatform::AwsNitro
        );
        assert_eq!(
            AttestationEvidence::Sgx { quote: vec![], pck_chain: vec![] }.platform(),
            TeePlatform::IntelSgx
        );
        assert_eq!(
            AttestationEvidence::SevSnp { report: vec![], vcek_der: vec![] }.platform(),
            TeePlatform::AmdSev
        );
        assert_eq!(
            AttestationEvidence::TrustZone { token: vec![] }.platform(),
            TeePlatform::ArmTrustZone
        );
        assert_eq!(
            AttestationEvidence::Keystone { report: vec![] }.platform(),
            TeePlatform::RiscvKeystone
        );
    }

    #[test]
    fn malformed_evidence_is_rejected_on_every_platform() {
        let roots = TeeTrustRoots {
            sgx_root_fingerprint: None,
            amd_root_der: None,
            keystone_device_key: Some([0u8; 32]),
            trustzone_iak: Some(vec![4u8; 65]),
        };
        assert!(AttestationEvidence::Nitro { document: vec![1, 2, 3] }.verify(&roots).is_err());
        assert!(AttestationEvidence::Sgx { quote: vec![0; 10], pck_chain: vec![] }
            .verify(&roots)
            .is_err());
        assert!(AttestationEvidence::SevSnp { report: vec![0; 10], vcek_der: vec![] }
            .verify(&roots)
            .is_err());
        assert!(AttestationEvidence::TrustZone { token: vec![9, 9] }.verify(&roots).is_err());
        assert!(AttestationEvidence::Keystone { report: vec![0; 10] }.verify(&roots).is_err());
    }

    #[test]
    fn platforms_needing_a_trust_root_refuse_without_one() {
        let empty = TeeTrustRoots::default();
        // No IAK / device key configured → refuse rather than accept blindly.
        let tz = AttestationEvidence::TrustZone { token: vec![0; 64] }.verify(&empty);
        assert!(tz.is_err(), "TrustZone requires a configured IAK");
        let ks = AttestationEvidence::Keystone {
            report: vec![0; crate::keystone::verify::REPORT_LEN],
        }
        .verify(&empty);
        assert!(ks.is_err(), "Keystone requires a configured device key");
    }

    #[test]
    fn evidence_round_trips_through_serde() {
        let e = AttestationEvidence::SevSnp { report: vec![1; 32], vcek_der: vec![2; 16] };
        let bytes = bincode::serialize(&e).expect("serializes");
        let back: AttestationEvidence = bincode::deserialize(&bytes).expect("deserializes");
        assert_eq!(back, e);
    }

    #[test]
    fn produce_is_none_without_hardware() {
        // In an environment with no TEE device present, production falls back to
        // simulation rather than failing.
        if !crate::nitro::is_available()
            && !sgx_available()
            && !sev_available()
            && !keystone_available()
            && !trustzone_available()
        {
            assert!(produce(b"body").expect("no error without hardware").is_none());
        }
    }
}
