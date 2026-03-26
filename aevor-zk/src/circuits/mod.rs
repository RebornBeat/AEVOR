//! Pre-built ZK circuits for common AEVOR operations.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

/// Proves that a value lies within [min, max] without revealing it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProofCircuit {
    /// Inclusive minimum.
    pub min: u64,
    /// Inclusive maximum.
    pub max: u64,
}

impl RangeProofCircuit {
    /// Returns the number of bits needed to represent the range.
    pub fn bit_width(&self) -> u32 {
        (self.max - self.min).next_power_of_two().trailing_zeros() + 1
    }
}

/// Proves membership in a Merkle tree at a specific depth.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePathCircuit {
    /// Tree depth (number of sibling hashes in a proof).
    pub depth: usize,
    /// Root hash this circuit verifies against.
    pub expected_root: Hash256,
}

impl MerklePathCircuit {
    /// Create a new Merkle path circuit.
    pub fn new(depth: usize, expected_root: Hash256) -> Self {
        Self { depth, expected_root }
    }

    /// Approximate constraint count: 2 * depth * hash_constraints.
    pub fn constraint_count(&self) -> usize { self.depth * 2 * 256 }
}

/// Proves knowledge of a valid signature without revealing the private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureCircuit {
    /// Hash of the message being signed.
    pub message_hash: Hash256,
}

/// Proves that a private balance transfer is valid (no negative balances).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceCircuit {
    /// Asset identifier.
    pub asset: Hash256,
    /// Maximum spendable amount (upper bound for the range proof).
    pub max_amount: u64,
}

/// A general-purpose privacy-preserving computation circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyPreservingCircuit {
    /// Ordered list of operations in this circuit.
    pub operations: Vec<String>,
    /// Unique circuit identifier.
    pub circuit_id: Hash256,
}

impl PrivacyPreservingCircuit {
    /// Create a new privacy circuit.
    pub fn new(operations: Vec<String>, circuit_id: Hash256) -> Self {
        Self { operations, circuit_id }
    }

    /// Number of operations in this circuit.
    pub fn op_count(&self) -> usize { self.operations.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    #[test]
    fn range_circuit_bit_width() {
        let c = RangeProofCircuit { min: 0, max: 255 };
        assert!(c.bit_width() >= 8);
    }

    #[test]
    fn merkle_circuit_constraint_count_scales_with_depth() {
        let c1 = MerklePathCircuit::new(8, Hash256::ZERO);
        let c2 = MerklePathCircuit::new(16, Hash256::ZERO);
        assert!(c2.constraint_count() > c1.constraint_count());
    }

    #[test]
    fn privacy_circuit_op_count() {
        let c = PrivacyPreservingCircuit::new(
            vec!["hash".into(), "verify".into()],
            Hash256([1u8; 32]),
        );
        assert_eq!(c.op_count(), 2);
    }
}
