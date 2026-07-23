//! Real ARM `TrustZone` attestation verification via the PSA attestation token —
//! pure Rust.
//!
//! `TrustZone` has no single vendor-independent quote format, but Arm standardizes
//! the *evidence*: the **PSA attestation token**, an EAT carried as a CBOR
//! `COSE_Sign1` object signed by the device's Initial Attestation Key (IAK). This
//! verifier checks that signature and extracts the standard PSA claims.
//!
//! Claims used (PSA claim keys, with EAT equivalents accepted):
//!
//! | claim | key | meaning |
//! |-------|-----|---------|
//! | nonce | `10` (EAT) or `-75008` (PSA) | freshness challenge |
//! | instance id | `256` (EAT ueid) or `-75009` | device instance |
//! | implementation id | `-75003` | hardware implementation |
//! | software components | `-75006` | array of measured components |
//!
//! Each software component is a map whose key `2` is the measurement value; those
//! measurements, in order, are the code identity checked against the registry.
//! The nonce claim carries the bound application data (AEVOR puts the
//! `ExecutionAttestation` body there, which is what the token freshness challenge
//! is for).

use ciborium::value::Value;

use crate::registry::VerifiedEnclave;
use crate::{TeeError, TeeResult};
use aevor_core::tee::TeePlatform;

const CLAIM_NONCE_EAT: i64 = 10;
const CLAIM_NONCE_PSA: i64 = -75008;
const CLAIM_INSTANCE_ID_EAT: i64 = 256;
const CLAIM_INSTANCE_ID_PSA: i64 = -75009;
const CLAIM_SOFTWARE_COMPONENTS: i64 = -75006;
const COMPONENT_MEASUREMENT_VALUE: i64 = 2;

fn fail(reason: impl Into<String>) -> TeeError {
    TeeError::AttestationFailed { reason: reason.into() }
}

fn as_bytes(v: &Value) -> TeeResult<Vec<u8>> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(fail("expected CBOR byte string")),
    }
}

/// Decode a `COSE_Sign1` into `(protected, payload, signature)`, accepting the
/// tagged (tag 18) or untagged form.
fn decode_cose_sign1(token: &[u8]) -> TeeResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let value: Value =
        ciborium::de::from_reader(token).map_err(|e| fail(format!("CBOR decode: {e}")))?;
    let arr = match value {
        Value::Tag(18, inner) => *inner,
        other => other,
    };
    let Value::Array(items) = arr else {
        return Err(fail("PSA token is not a COSE_Sign1 array"));
    };
    if items.len() != 4 {
        return Err(fail("COSE_Sign1 must have 4 elements"));
    }
    Ok((as_bytes(&items[0])?, as_bytes(&items[2])?, as_bytes(&items[3])?))
}

/// Reconstruct the canonical `Sig_structure` the IAK signed.
fn sig_structure(protected: &[u8], payload: &[u8]) -> TeeResult<Vec<u8>> {
    let s = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&s, &mut out)
        .map_err(|e| fail(format!("encode Sig_structure: {e}")))?;
    Ok(out)
}

fn claim(entries: &[(Value, Value)], key: i64) -> Option<&Value> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == i128::from(key)))
        .map(|(_, v)| v)
}

/// Verify a PSA attestation token against the device's Initial Attestation Key
/// (SEC1-encoded P-256 public key) and extract its identity claims.
///
/// Returns measurements in software-component order and `user_data` set to the
/// token's nonce claim — the challenge the device bound.
///
/// # Errors
/// Returns [`TeeError::AttestationFailed`] if the token is malformed, the IAK
/// signature does not verify, or the required claims are missing.
pub fn verify_token(token: &[u8], iak_public_key: &[u8]) -> TeeResult<VerifiedEnclave> {
    use p256::ecdsa::signature::Verifier as _;

    let (protected, payload, signature) = decode_cose_sign1(token)?;
    let signed = sig_structure(&protected, &payload)?;

    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(iak_public_key)
        .map_err(|e| fail(format!("IAK is not a valid P-256 key: {e}")))?;
    let sig = p256::ecdsa::Signature::from_slice(&signature)
        .map_err(|e| fail(format!("bad PSA token signature encoding: {e}")))?;
    key.verify(&signed, &sig)
        .map_err(|e| fail(format!("PSA token signature invalid: {e}")))?;

    let claims: Value =
        ciborium::de::from_reader(payload.as_slice()).map_err(|e| fail(format!("claims CBOR: {e}")))?;
    let Value::Map(entries) = claims else {
        return Err(fail("PSA claims are not a CBOR map"));
    };

    let nonce = claim(&entries, CLAIM_NONCE_EAT)
        .or_else(|| claim(&entries, CLAIM_NONCE_PSA))
        .ok_or_else(|| fail("PSA token has no nonce claim"))
        .and_then(as_bytes)?;

    let instance_id = claim(&entries, CLAIM_INSTANCE_ID_EAT)
        .or_else(|| claim(&entries, CLAIM_INSTANCE_ID_PSA))
        .map(as_bytes)
        .transpose()?
        .unwrap_or_default();

    let mut measurements = Vec::new();
    match claim(&entries, CLAIM_SOFTWARE_COMPONENTS) {
        Some(Value::Array(components)) => {
            for component in components {
                let Value::Map(fields) = component else {
                    return Err(fail("software component is not a map"));
                };
                if let Some(v) = claim(fields, COMPONENT_MEASUREMENT_VALUE) {
                    measurements.push(as_bytes(v)?);
                }
            }
        }
        _ => return Err(fail("PSA token has no software components claim")),
    }
    if measurements.is_empty() {
        return Err(fail("PSA token carries no component measurements"));
    }
    // The device instance is appended last so a network may pin it in addition to
    // the software measurements (registries match a prefix, so pinning it is opt-in).
    if !instance_id.is_empty() {
        measurements.push(instance_id);
    }

    Ok(VerifiedEnclave {
        platform: TeePlatform::ArmTrustZone,
        measurements,
        user_data: nonce.clone(),
        nonce,
        timestamp_ms: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_tokens_are_rejected() {
        assert!(verify_token(&[], &[]).is_err());
        assert!(verify_token(b"not cbor", &[4u8; 65]).is_err());
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Array(vec![Value::Integer(1.into())]), &mut buf).unwrap();
        assert!(verify_token(&buf, &[4u8; 65]).is_err());
    }

    #[test]
    fn genuine_token_verifies_and_yields_component_measurements() {
        use p256::ecdsa::{signature::Signer as _, SigningKey};

        // Build a real PSA token: claims → CBOR payload → COSE_Sign1 signed by IAK.
        let iak = SigningKey::from_bytes(&[3u8; 32].into()).unwrap();
        let iak_pub = iak.verifying_key().to_encoded_point(false);
        let body = b"execution-attestation-body".to_vec();

        let component = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("BL".to_string())),
            (Value::Integer(2.into()), Value::Bytes(vec![0xA1; 32])),
        ]);
        let component2 = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("PRoT".to_string())),
            (Value::Integer(2.into()), Value::Bytes(vec![0xB2; 32])),
        ]);
        let claims = Value::Map(vec![
            (Value::Integer(CLAIM_NONCE_EAT.into()), Value::Bytes(body.clone())),
            (Value::Integer(CLAIM_INSTANCE_ID_EAT.into()), Value::Bytes(vec![0xEE; 33])),
            (
                Value::Integer(CLAIM_SOFTWARE_COMPONENTS.into()),
                Value::Array(vec![component, component2]),
            ),
        ]);
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&claims, &mut payload).unwrap();
        let protected = vec![0xA1, 0x01, 0x26]; // {1: -7} = ES256
        let signed = sig_structure(&protected, &payload).unwrap();
        let sig: p256::ecdsa::Signature = iak.sign(&signed);

        let token_value = Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(sig.to_bytes().to_vec()),
        ]);
        let mut token = Vec::new();
        ciborium::ser::into_writer(&token_value, &mut token).unwrap();

        let verified = verify_token(&token, iak_pub.as_bytes()).expect("genuine token verifies");
        assert_eq!(verified.platform, TeePlatform::ArmTrustZone);
        assert_eq!(verified.user_data, body, "nonce carries the bound body");
        assert_eq!(verified.measurements[0], vec![0xA1; 32]);
        assert_eq!(verified.measurements[1], vec![0xB2; 32]);
        assert_eq!(verified.measurements[2], vec![0xEE; 33], "instance id appended last");

        // A different key must not verify the same token.
        let other = SigningKey::from_bytes(&[5u8; 32].into()).unwrap();
        let other_pub = other.verifying_key().to_encoded_point(false);
        assert!(verify_token(&token, other_pub.as_bytes()).is_err(), "wrong IAK rejected");

        // Tampering with the token payload breaks the signature.
        let mut tampered = token.clone();
        let n = tampered.len();
        tampered[n / 2] ^= 0xFF;
        assert!(verify_token(&tampered, iak_pub.as_bytes()).is_err(), "tampered token rejected");
    }
}
