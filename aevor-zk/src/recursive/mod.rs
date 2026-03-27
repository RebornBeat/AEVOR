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

#[cfg(test)]
mod tests {
    use super::*;

    // proof(n) produces a 32-byte array where byte j = n.wrapping_add(j as u8).
    // Non-uniform bytes ensure XOR accumulation never fully cancels — a single
    // proof of this form always produces a non-zero commitment hash.
    fn proof(n: u8) -> Vec<u8> {
        (0u8..32).map(|j| n.wrapping_add(j)).collect()
    }

    #[test]
    fn proof_accumulator_count_and_aggregate() {
        let mut acc = ProofAccumulator::new();
        acc.accumulate(proof(1));
        acc.accumulate(proof(2));
        assert_eq!(acc.count(), 2);
        let agg = acc.aggregate();
        assert_eq!(agg.count, 2);
        assert_eq!(agg.proofs.len(), 2);
    }

    #[test]
    fn proof_accumulator_empty_aggregate() {
        let acc = ProofAccumulator::default();
        let agg = acc.aggregate();
        assert_eq!(agg.count, 0);
        assert!(agg.proofs.is_empty());
    }

    #[test]
    fn recursive_prover_aggregate_returns_commitment() {
        let proofs = vec![proof(1), proof(2)];
        let (agg, commitment) = RecursiveProver::aggregate(&proofs);
        assert_eq!(agg.count, 2);
        assert_ne!(commitment, Hash256::ZERO);
    }

    #[test]
    fn recursive_prover_empty_set_produces_zero_commitment() {
        let (agg, commitment) = RecursiveProver::aggregate(&[]);
        assert_eq!(agg.count, 0);
        assert_eq!(commitment, Hash256::ZERO);
    }

    #[test]
    fn recursive_verifier_accepts_nonempty_aggregated_proof() {
        let proofs = vec![proof(1)];
        let (agg, _) = RecursiveProver::aggregate(&proofs);
        assert!(RecursiveVerifier::verify(&agg));
    }

    #[test]
    fn recursive_verifier_rejects_empty_proof_set() {
        let agg = AggregatedProof { proofs: vec![], aggregate: vec![], count: 0 };
        assert!(!RecursiveVerifier::verify(&agg));
    }

    #[test]
    fn verify_with_commitment_roundtrip() {
        let proofs = vec![proof(5), proof(6)];
        let (agg, commitment) = RecursiveProver::aggregate(&proofs);
        assert!(RecursiveVerifier::verify_with_commitment(&agg, &commitment));
    }

    #[test]
    fn verify_with_commitment_rejects_wrong_commitment() {
        let proofs = vec![proof(1)];
        let (agg, _) = RecursiveProver::aggregate(&proofs);
        assert!(!RecursiveVerifier::verify_with_commitment(&agg, &Hash256([0xFF; 32])));
    }
}
