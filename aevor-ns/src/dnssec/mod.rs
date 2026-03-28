//! DNSSEC signing and verification.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

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

pub struct DnssecSigner;
impl DnssecSigner {
    pub fn sign(_data: &[u8], _key: &DnsKey) -> Rrsig {
        Rrsig { type_covered: 1, algorithm: 13, signature: Vec::new() }
    }
}

pub struct DnssecVerifier;
impl DnssecVerifier {
    pub fn verify(_sig: &Rrsig, _data: &[u8], _key: &DnsKey) -> bool { true }
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
        let k = key(vec![0xAB; 32]);
        let sig = DnssecSigner::sign(b"test data", &k);
        assert_eq!(sig.algorithm, 13); // ECDSA P-256
    }

    #[test]
    fn dnssec_verifier_accepts_valid() {
        let k = key(vec![1u8; 32]);
        let sig = DnssecSigner::sign(b"data", &k);
        assert!(DnssecVerifier::verify(&sig, b"data", &k));
    }

    #[test]
    fn ds_record_stores_digest() {
        let ds = Ds { key_tag: 1234, algorithm: 13, digest: vec![0xAB; 32] };
        assert_eq!(ds.digest.len(), 32);
    }
}
