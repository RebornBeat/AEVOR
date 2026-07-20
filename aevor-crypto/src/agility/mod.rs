//! Crypto agility: sign and verify through a scheme-tagged envelope.
//!
//! This is the seam that lets AEVOR carry classical and post-quantum signatures
//! under one wire type ([`MultiSignature`]) and switch between schemes — or
//! between two post-quantum schemes — without touching anything that stores or
//! moves a signature. Adding a new scheme is:
//!
//! 1. a variant on `aevor_core::crypto::SignatureSchemeId` (already reserved for
//!    ML-DSA / FN-DSA / SLH-DSA / FAEST / hybrids), and
//! 2. one arm in [`verify_multi`] (+ optionally a [`Signer`] impl).
//!
//! Ed25519 is fully implemented here. Post-quantum schemes are *recognized* but
//! return [`MultiVerify::Unsupported`] until their backends land (e.g. real
//! ML-DSA in register item B2), so callers can always distinguish "signature is
//! invalid" from "this build can't check that scheme yet".

use aevor_core::crypto::{MultiPublicKey, MultiSignature, SignatureSchemeId};

use crate::signatures::Ed25519KeyPair;

/// Anything that can produce a scheme-tagged signature.
pub trait Signer {
    /// The scheme this signer uses.
    fn scheme(&self) -> SignatureSchemeId;
    /// Sign `message`, returning a tagged envelope.
    fn sign_message(&self, message: &[u8]) -> MultiSignature;
    /// This signer's scheme-tagged public key.
    fn public_key_multi(&self) -> MultiPublicKey;
}

/// Result of verifying a [`MultiSignature`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiVerify {
    /// Signature is valid for the message and key.
    Valid,
    /// Signature is well-formed but does not verify.
    Invalid,
    /// The signature's scheme and the key's scheme disagree.
    SchemeMismatch,
    /// The scheme is recognized but not implemented in this build.
    Unsupported(SignatureSchemeId),
}

impl MultiVerify {
    /// True only for [`MultiVerify::Valid`].
    #[must_use]
    pub fn is_valid(self) -> bool {
        matches!(self, MultiVerify::Valid)
    }
}

/// Verify a scheme-tagged signature by dispatching on its scheme id.
///
/// Returns [`MultiVerify::SchemeMismatch`] if the signature and key schemes
/// differ, [`MultiVerify::Unsupported`] for a recognized-but-unimplemented
/// scheme, otherwise [`MultiVerify::Valid`] / [`MultiVerify::Invalid`].
#[must_use]
pub fn verify_multi(
    message: &[u8],
    signature: &MultiSignature,
    public_key: &MultiPublicKey,
) -> MultiVerify {
    if signature.scheme != public_key.scheme {
        return MultiVerify::SchemeMismatch;
    }

    match signature.scheme {
        SignatureSchemeId::Ed25519 => {
            let Ok(pk): Result<[u8; 32], _> = public_key.bytes.as_slice().try_into() else {
                return MultiVerify::Invalid;
            };
            let Ok(sig): Result<[u8; 64], _> = signature.bytes.as_slice().try_into() else {
                return MultiVerify::Invalid;
            };
            if Ed25519KeyPair::verify_raw(&pk, message, &sig) {
                MultiVerify::Valid
            } else {
                MultiVerify::Invalid
            }
        }
        SignatureSchemeId::MlDsa65 => {
            if crate::post_quantum::ml_dsa::verify(&public_key.bytes, message, &signature.bytes) {
                MultiVerify::Valid
            } else {
                MultiVerify::Invalid
            }
        }
        SignatureSchemeId::HybridEd25519MlDsa65 => {
            // Packed public key: 32 (Ed25519) ‖ 1952 (ML-DSA-65).
            // Packed signature:  64 (Ed25519) ‖ 3309 (ML-DSA-65).
            const ED_PK: usize = 32;
            const ED_SIG: usize = 64;
            if public_key.bytes.len() != ED_PK + 1952 || signature.bytes.len() != ED_SIG + 3309 {
                return MultiVerify::Invalid;
            }
            let Ok(ed_pk): Result<[u8; ED_PK], _> = public_key.bytes[..ED_PK].try_into() else {
                return MultiVerify::Invalid;
            };
            let Ok(ed_sig): Result<[u8; ED_SIG], _> = signature.bytes[..ED_SIG].try_into() else {
                return MultiVerify::Invalid;
            };
            let ml_pk = &public_key.bytes[ED_PK..];
            let ml_sig = &signature.bytes[ED_SIG..];
            // BOTH components must verify — forging requires breaking both.
            let classical_ok = Ed25519KeyPair::verify_raw(&ed_pk, message, &ed_sig);
            let pq_ok = crate::post_quantum::ml_dsa::verify(ml_pk, message, ml_sig);
            if classical_ok && pq_ok {
                MultiVerify::Valid
            } else {
                MultiVerify::Invalid
            }
        }
        // Recognized but not yet implemented in this build. When the backend
        // lands this arm returns Valid/Invalid instead.
        other => MultiVerify::Unsupported(other),
    }
}

impl Signer for Ed25519KeyPair {
    fn scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::Ed25519
    }

    fn sign_message(&self, message: &[u8]) -> MultiSignature {
        // Ed25519Signature(pub Signature([u8; 64]))
        let sig = self.sign(message);
        MultiSignature::new(SignatureSchemeId::Ed25519, sig.0 .0.to_vec())
    }

    fn public_key_multi(&self) -> MultiPublicKey {
        MultiPublicKey::new(SignatureSchemeId::Ed25519, self.public_key_bytes().to_vec())
    }
}

impl Signer for crate::post_quantum::ml_dsa::MlDsa65KeyPair {
    fn scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::MlDsa65
    }

    fn sign_message(&self, message: &[u8]) -> MultiSignature {
        // ML-DSA signing is practically infallible (internal rejection loop);
        // the trait is infallible, matching Ed25519.
        let sig = self.sign(message).expect("ML-DSA-65 signing");
        MultiSignature::new(SignatureSchemeId::MlDsa65, sig)
    }

    fn public_key_multi(&self) -> MultiPublicKey {
        MultiPublicKey::new(SignatureSchemeId::MlDsa65, self.public_key_bytes().to_vec())
    }
}

impl Signer for crate::post_quantum::HybridKeyPair {
    fn scheme(&self) -> SignatureSchemeId {
        SignatureSchemeId::HybridEd25519MlDsa65
    }

    fn sign_message(&self, message: &[u8]) -> MultiSignature {
        // Pack Ed25519 (64) ‖ ML-DSA-65 (3309).
        let hybrid = self.sign(message);
        let mut bytes = Vec::with_capacity(64 + 3309);
        bytes.extend_from_slice(&hybrid.classical.0 .0);
        bytes.extend_from_slice(&hybrid.post_quantum.0);
        MultiSignature::new(SignatureSchemeId::HybridEd25519MlDsa65, bytes)
    }

    fn public_key_multi(&self) -> MultiPublicKey {
        // Pack Ed25519 pk (32) ‖ ML-DSA-65 pk (1952).
        let mut bytes = Vec::with_capacity(32 + 1952);
        bytes.extend_from_slice(&self.classical_public_key_bytes());
        bytes.extend_from_slice(&self.ml_dsa_public_key_bytes());
        MultiPublicKey::new(SignatureSchemeId::HybridEd25519MlDsa65, bytes)
    }
}

/// Sign a transaction body with a wallet of any scheme, producing the canonical
/// [`SignedTransaction`](aevor_core::transaction::SignedTransaction).
///
/// The wallet's scheme-tagged public key is stamped onto the body so the
/// signature and key always agree, and the signature covers
/// [`Transaction::signing_bytes`](aevor_core::transaction::Transaction::signing_bytes).
#[must_use]
pub fn sign_transaction<S: Signer>(
    mut transaction: aevor_core::transaction::Transaction,
    wallet: &S,
) -> aevor_core::transaction::SignedTransaction {
    transaction.sender_public_key = wallet.public_key_multi();
    let signature = wallet.sign_message(&transaction.signing_bytes());
    aevor_core::transaction::SignedTransaction {
        transaction,
        signature,
        multi_signatures: Vec::new(),
        privacy_proof: None,
    }
}

/// Verify a signed transaction's sender signature (any scheme) against its body.
///
/// Returns `true` only if the primary signature is valid for the body's
/// [`signing_bytes`](aevor_core::transaction::Transaction::signing_bytes) under
/// the body's `sender_public_key`.
#[must_use]
pub fn verify_transaction(signed: &aevor_core::transaction::SignedTransaction) -> bool {
    verify_multi(
        &signed.transaction.signing_bytes(),
        &signed.signature,
        &signed.transaction.sender_public_key,
    )
    .is_valid()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed([7u8; 32])
    }

    #[test]
    fn ed25519_sign_then_verify_through_envelope() {
        let kp = keypair();
        let msg = b"transfer 10 to alice";
        let sig = kp.sign_message(msg);
        let pk = kp.public_key_multi();
        assert_eq!(sig.scheme, SignatureSchemeId::Ed25519);
        assert_eq!(sig.len(), 64);
        assert_eq!(pk.len(), 32);
        assert_eq!(verify_multi(msg, &sig, &pk), MultiVerify::Valid);
    }

    #[test]
    fn tampered_message_fails() {
        let kp = keypair();
        let sig = kp.sign_message(b"pay 10");
        let pk = kp.public_key_multi();
        assert_eq!(verify_multi(b"pay 1000", &sig, &pk), MultiVerify::Invalid);
    }

    #[test]
    fn scheme_mismatch_is_reported() {
        let kp = keypair();
        let sig = kp.sign_message(b"m");
        // Same key bytes but claim a different scheme.
        let wrong_pk = MultiPublicKey::new(SignatureSchemeId::MlDsa65, kp.public_key_bytes().to_vec());
        assert_eq!(verify_multi(b"m", &sig, &wrong_pk), MultiVerify::SchemeMismatch);
    }

    #[test]
    fn unimplemented_pq_scheme_is_unsupported_not_invalid() {
        // A verifier must distinguish "can't check yet" from "wrong signature".
        // SLH-DSA is still unimplemented, so it must report Unsupported.
        let sig = MultiSignature::new(SignatureSchemeId::SlhDsa128s, vec![0u8; 7856]);
        let pk = MultiPublicKey::new(SignatureSchemeId::SlhDsa128s, vec![0u8; 32]);
        assert_eq!(
            verify_multi(b"m", &sig, &pk),
            MultiVerify::Unsupported(SignatureSchemeId::SlhDsa128s)
        );
    }

    #[test]
    fn real_hybrid_roundtrips_and_requires_both_halves() {
        // A hybrid wallet: Ed25519 + ML-DSA-65 packed into one agility signature.
        use crate::post_quantum::HybridKeyPair;
        let kp = HybridKeyPair::generate().unwrap();
        let msg = b"hybrid-signed transfer";
        let sig = kp.sign_message(msg);
        let pk = kp.public_key_multi();
        assert_eq!(sig.scheme, SignatureSchemeId::HybridEd25519MlDsa65);
        assert_eq!(verify_multi(msg, &sig, &pk), MultiVerify::Valid);

        // Safety when Ed25519 falls: corrupt ONLY the ML-DSA half (bytes after
        // the 64-byte Ed25519 signature) while leaving the classical half valid.
        // An adversary who forged Ed25519 but cannot forge ML-DSA lands here —
        // the hybrid signature must still be rejected.
        let mut tampered = sig.clone();
        let ml_start = 64;
        tampered.bytes[ml_start] ^= 0xFF;
        assert_eq!(verify_multi(msg, &tampered, &pk), MultiVerify::Invalid);

        // Symmetrically, corrupting only the Ed25519 half also fails.
        let mut tampered2 = sig.clone();
        tampered2.bytes[0] ^= 0xFF;
        assert_eq!(verify_multi(msg, &tampered2, &pk), MultiVerify::Invalid);
    }

    #[test]
    fn real_ml_dsa_65_roundtrips_through_agility() {
        use crate::post_quantum::ml_dsa::MlDsa65KeyPair;
        let kp = MlDsa65KeyPair::generate().unwrap();
        let msg = b"post-quantum transfer 10 to alice";
        let sig = kp.sign_message(msg);
        let pk = kp.public_key_multi();
        assert_eq!(sig.scheme, SignatureSchemeId::MlDsa65);
        assert!(sig.is_post_quantum());
        assert_eq!(verify_multi(msg, &sig, &pk), MultiVerify::Valid);
        // Tampering is rejected as Invalid (not Unsupported).
        assert_eq!(verify_multi(b"different", &sig, &pk), MultiVerify::Invalid);
    }

    #[test]
    fn post_quantum_flag_tracks_scheme() {
        assert!(!keypair().sign_message(b"m").is_post_quantum());
        assert!(MultiSignature::new(SignatureSchemeId::MlDsa65, vec![]).is_post_quantum());
        assert!(MultiSignature::new(SignatureSchemeId::HybridEd25519MlDsa65, vec![]).is_post_quantum());
    }
}
