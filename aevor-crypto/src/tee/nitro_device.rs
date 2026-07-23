//! AWS Nitro producer side: request an attestation document from the Nitro
//! Security Module (NSM) over its device interface.
//!
//! Compiles everywhere (the NSM driver crate is pure Rust); returns a document
//! only when running inside a real Nitro Enclave, where the NSM device exists.
//! Off-hardware, `nsm_init` fails and this returns an error rather than a stub
//! value — so the same binary runs in the sandbox (returning the error) and on an
//! enclave (returning a real document).

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;

/// Request a signed attestation document from the NSM, binding `user_data` (the
/// AEVOR `ExecutionAttestation` body) and an optional freshness `nonce`. The
/// returned bytes are a CBOR `COSE_Sign1` document that
/// [`super::nitro::verify`] checks.
///
/// # Errors
/// Returns an error if the NSM device is unavailable (not inside a Nitro Enclave)
/// or the NSM returns a non-attestation response.
pub fn request_attestation(user_data: Vec<u8>, nonce: Option<Vec<u8>>) -> Result<Vec<u8>, String> {
    let fd = nsm_init();
    if fd < 0 {
        return Err("NSM device unavailable (not running inside a Nitro Enclave)".to_string());
    }
    let request = Request::Attestation {
        user_data: Some(ByteBuf::from(user_data)),
        nonce: nonce.map(ByteBuf::from),
        public_key: None,
    };
    let response = nsm_process_request(fd, request);
    nsm_exit(fd);
    match response {
        Response::Attestation { document } => Ok(document),
        other => Err(format!("unexpected NSM response: {other:?}")),
    }
}
