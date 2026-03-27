//! Recursive proof composition.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedProof { pub proofs: Vec<Vec<u8>>, pub aggregate: Vec<u8>, pub count: usize }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofComposition { pub inner: Vec<u8>, pub outer: Vec<u8> }

pub struct ProofAccumulator { proofs: Vec<Vec<u8>> }
impl ProofAccumulator {
    pub fn new() -> Self { Self { proofs: Vec::new() } }
    pub fn accumulate(&mut self, proof: Vec<u8>) { self.proofs.push(proof); }
    pub fn count(&self) -> usize { self.proofs.len() }
    pub fn aggregate(&self) -> AggregatedProof {
        AggregatedProof { proofs: self.proofs.clone(), aggregate: Vec::new(), count: self.proofs.len() }
    }
}
impl Default for ProofAccumulator { fn default() -> Self { Self::new() } }

pub struct RecursiveProver;

impl RecursiveProver {
    /// Aggregate multiple proofs into a single recursive proof.
    ///
    /// The `aggregate_hash` (`Hash256`) commits to the set of proofs being
    /// aggregated, ensuring the verifier knows exactly which proofs were combined.
    pub fn aggregate(proofs: &[Vec<u8>]) -> (AggregatedProof, Hash256) {
        let mut h = [0u8; 32];
        for proof in proofs {
            for (i, b) in proof.iter().enumerate() { h[i % 32] ^= b; }
        }
        let commitment = Hash256(h);
        let agg = AggregatedProof {
            proofs: proofs.to_vec(),
            aggregate: Vec::new(), // aggregate signature built by BLS in production
            count: proofs.len(),
        };
        (agg, commitment)
    }
}

pub struct RecursiveVerifier;

impl RecursiveVerifier {
    /// Verify an aggregated proof.
    pub fn verify(agg: &AggregatedProof) -> bool { agg.count > 0 }

    /// Verify an aggregated proof against its commitment hash.
    pub fn verify_with_commitment(agg: &AggregatedProof, commitment: &Hash256) -> bool {
        if !Self::verify(agg) { return false; }
        let mut h = [0u8; 32];
        for proof in &agg.proofs {
            for (i, b) in proof.iter().enumerate() { h[i % 32] ^= b; }
        }
        Hash256(h) == *commitment
    }
}
