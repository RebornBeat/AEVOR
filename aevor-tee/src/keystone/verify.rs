//! Real RISC-V Keystone attestation report verification — pure Rust.
//!
//! A Keystone report is a fixed C structure produced by the Security Monitor:
//!
//! ```text
//! struct enclave_report_t { byte hash[64]; uint64 data_len; byte data[1024]; byte signature[64]; }
//! struct sm_report_t      { byte hash[64]; byte public_key[32]; byte signature[64]; }
//! struct report_t         { enclave_report_t enclave; sm_report_t sm; byte dev_public_key[32]; }
//! ```
//!
//! Sizes: enclave report 1160, SM report 160, device key 32 — 1352 bytes total.
//!
//! Trust chains through two Ed25519 signatures:
//! 1. the **device** key signs the SM report (`sm.hash ‖ sm.public_key`), proving
//!    the Security Monitor itself is the one the hardware vendor provisioned;
//! 2. the **SM** key signs the enclave report (`enclave.hash ‖ data[..data_len]`),
//!    proving the enclave measurement and the data the enclave bound.
//!
//! So verifying against a trusted device public key establishes the whole chain.

use crate::registry::VerifiedEnclave;
use crate::{TeeError, TeeResult};
use aevor_core::tee::TeePlatform;

const ENCLAVE_HASH_LEN: usize = 64;
const ENCLAVE_DATA_MAX: usize = 1024;
const SIG_LEN: usize = 64;
const KEY_LEN: usize = 32;
const ENCLAVE_REPORT_LEN: usize = ENCLAVE_HASH_LEN + 8 + ENCLAVE_DATA_MAX + SIG_LEN; // 1160
const SM_HASH_OFF: usize = ENCLAVE_REPORT_LEN;
const SM_KEY_OFF: usize = SM_HASH_OFF + 64;
const SM_SIG_OFF: usize = SM_KEY_OFF + KEY_LEN;
const DEV_KEY_OFF: usize = SM_SIG_OFF + SIG_LEN;
/// Total size of a Keystone attestation report.
pub const REPORT_LEN: usize = DEV_KEY_OFF + KEY_LEN; // 1352

fn fail(reason: impl Into<String>) -> TeeError {
    TeeError::AttestationFailed { reason: reason.into() }
}

fn verify_ed25519(key: &[u8], message: &[u8], signature: &[u8], what: &str) -> TeeResult<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let key_bytes: [u8; 32] =
        key.try_into().map_err(|_| fail(format!("{what}: public key is not 32 bytes")))?;
    let sig_bytes: [u8; 64] =
        signature.try_into().map_err(|_| fail(format!("{what}: signature is not 64 bytes")))?;
    let vk = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| fail(format!("{what}: invalid public key: {e}")))?;
    // `verify_strict` (not `verify`): it rejects small-order and non-canonical
    // public keys. Plain `verify` would accept an all-zero signature against the
    // identity point — a report of all zeros would "verify". Strict verification
    // closes that.
    vk.verify_strict(message, &Signature::from_bytes(&sig_bytes))
        .map_err(|e| fail(format!("{what}: signature invalid: {e}")))
}

/// Verify a Keystone report against the trusted device public key (the hardware
/// root of trust, supplied by configuration), returning the normalized enclave
/// identity with measurements `[enclave_hash, sm_hash]` and `user_data` set to the
/// data the enclave bound.
///
/// # Errors
/// Returns [`TeeError::AttestationFailed`] if the report is truncated, declares a
/// data length beyond its buffer, does not match the trusted device key, or either
/// signature in the chain fails to verify.
pub fn verify_report(report: &[u8], trusted_device_key: &[u8; 32]) -> TeeResult<VerifiedEnclave> {
    if report.len() < REPORT_LEN {
        return Err(fail("Keystone report shorter than 1352 bytes"));
    }
    let enclave_hash = &report[0..ENCLAVE_HASH_LEN];
    let data_len = {
        let mut b = [0u8; 8];
        b.copy_from_slice(&report[ENCLAVE_HASH_LEN..ENCLAVE_HASH_LEN + 8]);
        usize::try_from(u64::from_le_bytes(b)).map_err(|_| fail("data length out of range"))?
    };
    if data_len > ENCLAVE_DATA_MAX {
        return Err(fail("Keystone report declares data beyond its 1024-byte buffer"));
    }
    let data_off = ENCLAVE_HASH_LEN + 8;
    let data = &report[data_off..data_off + data_len];
    let enclave_sig = &report[data_off + ENCLAVE_DATA_MAX..data_off + ENCLAVE_DATA_MAX + SIG_LEN];
    let sm_hash = &report[SM_HASH_OFF..SM_HASH_OFF + 64];
    let sm_key = &report[SM_KEY_OFF..SM_KEY_OFF + KEY_LEN];
    let sm_sig = &report[SM_SIG_OFF..SM_SIG_OFF + SIG_LEN];
    let dev_key = &report[DEV_KEY_OFF..DEV_KEY_OFF + KEY_LEN];

    // The report must come from the device we trust.
    if dev_key != trusted_device_key {
        return Err(fail("Keystone report device key does not match the trusted root"));
    }

    // 1. Device key signs the SM report.
    let mut sm_msg = Vec::with_capacity(64 + KEY_LEN);
    sm_msg.extend_from_slice(sm_hash);
    sm_msg.extend_from_slice(sm_key);
    verify_ed25519(dev_key, &sm_msg, sm_sig, "Keystone SM report")?;

    // 2. SM key signs the enclave report.
    let mut enclave_msg = Vec::with_capacity(ENCLAVE_HASH_LEN + data_len);
    enclave_msg.extend_from_slice(enclave_hash);
    enclave_msg.extend_from_slice(data);
    verify_ed25519(sm_key, &enclave_msg, enclave_sig, "Keystone enclave report")?;

    Ok(VerifiedEnclave {
        platform: TeePlatform::RiscvKeystone,
        measurements: vec![enclave_hash.to_vec(), sm_hash.to_vec()],
        user_data: data.to_vec(),
        nonce: Vec::new(),
        timestamp_ms: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_reports_are_rejected() {
        assert!(verify_report(&[], &[0u8; 32]).is_err());
        assert!(verify_report(&[0u8; 500], &[0u8; 32]).is_err());
    }

    #[test]
    fn wrong_device_key_is_rejected() {
        let report = vec![0u8; REPORT_LEN]; // device key field is all zeros
        assert!(verify_report(&report, &[0xAA; 32]).is_err(), "device key must match the root");
    }

    #[test]
    fn oversized_data_length_is_rejected() {
        let mut report = vec![0u8; REPORT_LEN];
        report[ENCLAVE_HASH_LEN..ENCLAVE_HASH_LEN + 8]
            .copy_from_slice(&(ENCLAVE_DATA_MAX as u64 + 1).to_le_bytes());
        assert!(verify_report(&report, &[0u8; 32]).is_err(), "must not read past the buffer");
    }

    #[test]
    fn unsigned_report_never_verifies() {
        // All-zero report with a matching (zero) device key: the ed25519 chain must
        // still reject it — a zero signature is not valid.
        let report = vec![0u8; REPORT_LEN];
        assert!(verify_report(&report, &[0u8; 32]).is_err());
    }

    #[test]
    fn real_signature_chain_verifies_and_yields_measurements() {
        use ed25519_dalek::{Signer as _, SigningKey};
        // Build a genuine report: device key signs the SM report, SM key signs the
        // enclave report. This exercises the full chain end to end.
        let dev = SigningKey::from_bytes(&[7u8; 32]);
        let sm = SigningKey::from_bytes(&[9u8; 32]);
        let dev_pub = dev.verifying_key().to_bytes();
        let sm_pub = sm.verifying_key().to_bytes();
        let enclave_hash = [0x11u8; 64];
        let sm_hash = [0x22u8; 64];
        let payload = b"execution-attestation-body";

        let mut report = vec![0u8; REPORT_LEN];
        report[0..64].copy_from_slice(&enclave_hash);
        report[64..72].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        report[72..72 + payload.len()].copy_from_slice(payload);

        let mut enclave_msg = Vec::new();
        enclave_msg.extend_from_slice(&enclave_hash);
        enclave_msg.extend_from_slice(payload);
        let enclave_sig = sm.sign(&enclave_msg).to_bytes();
        report[72 + ENCLAVE_DATA_MAX..72 + ENCLAVE_DATA_MAX + 64].copy_from_slice(&enclave_sig);

        report[SM_HASH_OFF..SM_HASH_OFF + 64].copy_from_slice(&sm_hash);
        report[SM_KEY_OFF..SM_KEY_OFF + 32].copy_from_slice(&sm_pub);
        let mut sm_msg = Vec::new();
        sm_msg.extend_from_slice(&sm_hash);
        sm_msg.extend_from_slice(&sm_pub);
        let sm_sig = dev.sign(&sm_msg).to_bytes();
        report[SM_SIG_OFF..SM_SIG_OFF + 64].copy_from_slice(&sm_sig);
        report[DEV_KEY_OFF..DEV_KEY_OFF + 32].copy_from_slice(&dev_pub);

        let verified = verify_report(&report, &dev_pub).expect("genuine report verifies");
        assert_eq!(verified.platform, TeePlatform::RiscvKeystone);
        assert_eq!(verified.measurements, vec![enclave_hash.to_vec(), sm_hash.to_vec()]);
        assert_eq!(verified.user_data, payload.to_vec());

        // Tampering with the bound data breaks the enclave signature.
        let mut tampered = report.clone();
        tampered[72] ^= 0xFF;
        assert!(verify_report(&tampered, &dev_pub).is_err(), "tampered payload rejected");

        // Substituting the SM key breaks the device signature.
        let mut swapped = report;
        swapped[SM_KEY_OFF] ^= 0xFF;
        assert!(verify_report(&swapped, &dev_pub).is_err(), "substituted SM key rejected");
    }
}
