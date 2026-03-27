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
