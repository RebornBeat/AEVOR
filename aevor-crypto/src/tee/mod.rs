//! Trusted Execution Environment (TEE) attestation.
//!
//! Proof-of-Uncorruption's production root of trust: a hardware TEE attests that a
//! specific, measured code binary executed inside a genuine enclave and produced a
//! given output. A verifier checks the attestation instead of re-executing.
//!
//! [`nitro`] implements real AWS Nitro Enclaves attestation *verification* in pure
//! Rust (no platform SDK, so it builds and runs anywhere a verifier runs). The
//! producer side — requesting an attestation document from the Nitro Security
//! Module — is a hardware device interaction ([`nitro_device`]) that compiles
//! everywhere but only returns a document when run inside a real enclave.
//!
//! Corruption detection then follows doc 22: a verifier accepts a producer only if
//! the attestation's code measurement (PCRs) is in the network-agreed registry, the
//! chain validates to the pinned AWS root, the signature verifies, and the bound
//! `user_data` equals the expected `ExecutionAttestation` body.

pub mod nitro;
pub mod nitro_device;
