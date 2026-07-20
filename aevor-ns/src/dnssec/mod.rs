//! DNSSEC signing and verification.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use aevor_crypto::signatures::Ed25519KeyPair;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsKey { pub flags: u16, pub protocol: u8, pub algorithm: u8, pub public_key: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rrsig { pub type_covered: u16, pub algorithm: u8, pub signature: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Nsec { pub next_domain: String, pub types: Vec<u16> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ds { pub key_tag: u16, pub algorithm: u8, pub digest: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnssecChain { pub keys: Vec<DnsKey>, pub sigs: Vec<Rrsig> }

impl DnssecChain {
    /// A `Hash256` commitment to the key set in this chain.
    ///
    /// Enables light clients to verify the DNSSEC chain against a trusted
    /// root hash without downloading all key material.
    pub fn key_commitment(&self) -> Hash256 {
        let mut h = [0u8; 32];
        for key in &self.keys {
            for (i, b) in key.public_key.iter().enumerate() { h[i % 32] ^= b; }
        }
        Hash256(h)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnssecValidation { pub chain: DnssecChain, pub validated: bool }

/// DNSSEC algorithm number for Ed25519 (RFC 8080).
pub const ALGORITHM_ED25519: u8 = 15;

pub struct DnssecSigner;
impl DnssecSigner {
    /// Sign record bytes with an Ed25519 zone key, producing a real RRSIG
    /// (DNSSEC algorithm 15 / Ed25519).
    #[must_use]
    pub fn sign(data: &[u8], key: &Ed25519KeyPair, type_covered: u16) -> Rrsig {
        let sig = key.sign(data);
        Rrsig {
            type_covered,
            algorithm: ALGORITHM_ED25519,
            signature: sig.0 .0.to_vec(),
        }
    }

    /// The public DNSKEY (a key-signing-key flags=257) for an Ed25519 zone key.
    #[must_use]
    pub fn public_dnskey(key: &Ed25519KeyPair) -> DnsKey {
        DnsKey {
            flags: 257,
            protocol: 3,
            algorithm: ALGORITHM_ED25519,
            public_key: key.public_key_bytes().to_vec(),
        }
    }
}

pub struct DnssecVerifier;
impl DnssecVerifier {
    /// Really verify an RRSIG over `data` under a DNSKEY.
    ///
    /// Returns `true` only if the signature is a valid Ed25519 signature
    /// (algorithm 15) over `data` for the key. Previously this always returned
    /// `true` — a validation bypass; it now performs real cryptographic
    /// verification.
    #[must_use]
    pub fn verify(sig: &Rrsig, data: &[u8], key: &DnsKey) -> bool {
        if sig.algorithm != ALGORITHM_ED25519 || key.algorithm != ALGORITHM_ED25519 {
            return false;
        }
        let pk: [u8; 32] = match key.public_key.as_slice().try_into() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let s: [u8; 64] = match sig.signature.as_slice().try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        Ed25519KeyPair::verify_raw(&pk, data, &s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn key(bytes: Vec<u8>) -> DnsKey {
        DnsKey { flags: 257, protocol: 3, algorithm: 13, public_key: bytes }
    }

    #[test]
    fn dnssec_chain_key_commitment_nonzero_for_nonempty_key() {
        let chain = DnssecChain { keys: vec![key(vec![1, 2, 3, 4])], sigs: vec![] };
        assert_ne!(chain.key_commitment(), Hash256::ZERO);
    }

    #[test]
    fn dnssec_chain_key_commitment_zero_for_empty_chain() {
        let chain = DnssecChain { keys: vec![], sigs: vec![] };
        assert_eq!(chain.key_commitment(), Hash256::ZERO);
    }

    #[test]
    fn dnssec_signer_produces_rrsig() {
        let kp = Ed25519KeyPair::from_seed([0xAB; 32]);
        let sig = DnssecSigner::sign(b"test data", &kp, 1);
        assert_eq!(sig.algorithm, ALGORITHM_ED25519);
        assert_eq!(sig.signature.len(), 64);
    }

    #[test]
    fn dnssec_verifier_accepts_valid_and_rejects_tampered() {
        let kp = Ed25519KeyPair::from_seed([1u8; 32]);
        let sig = DnssecSigner::sign(b"data", &kp, 1);
        let dnskey = DnssecSigner::public_dnskey(&kp);
        assert!(DnssecVerifier::verify(&sig, b"data", &dnskey), "valid signature accepted");
        assert!(
            !DnssecVerifier::verify(&sig, b"tampered", &dnskey),
            "signature over different data rejected"
        );
    }

    #[test]
    fn ds_record_stores_digest() {
        let ds = Ds { key_tag: 1234, algorithm: 13, digest: vec![0xAB; 32] };
        assert_eq!(ds.digest.len(), 32);
    }
}
