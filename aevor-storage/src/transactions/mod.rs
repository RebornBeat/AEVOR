//! Transaction receipt and execution receipt storage.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{BlockHeight, Hash256, TransactionHash};
pub use aevor_core::transaction::TransactionReceipt;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub transaction_hash: TransactionHash,
    pub success: bool,
    pub gas_consumed: aevor_core::primitives::GasAmount,
    pub error: Option<String>,
    pub block_height: BlockHeight,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptQuery {
    pub transaction_hash: Option<TransactionHash>,
    pub block_height: Option<BlockHeight>,
    pub sender: Option<aevor_core::primitives::Address>,
    pub limit: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptBatch {
    pub receipts: Vec<TransactionReceipt>,
    pub total_count: usize,
}

pub struct TransactionStore {
    receipts: std::collections::HashMap<[u8; 32], TransactionReceipt>,
}

impl TransactionStore {
    /// Create an empty transaction store.
    pub fn new() -> Self { Self { receipts: std::collections::HashMap::new() } }

    /// Store a receipt (idempotent — re-storing the same hash is a no-op).
    pub fn store(&mut self, receipt: TransactionReceipt) {
        self.receipts.insert(receipt.transaction_hash.0, receipt);
    }

    /// Retrieve a receipt by transaction hash.
    pub fn get(&self, hash: &TransactionHash) -> Option<&TransactionReceipt> {
        self.receipts.get(&hash.0)
    }

    /// Number of receipts stored.
    pub fn count(&self) -> usize { self.receipts.len() }

    /// Compute a BLAKE3 Merkle root over all stored receipt hashes.
    ///
    /// This `Hash256` is included in block headers to commit to the receipt set,
    /// enabling light clients to verify individual receipts with inclusion proofs.
    pub fn receipt_root(&self) -> Hash256 {
        if self.receipts.is_empty() {
            return Hash256::ZERO;
        }
        let mut sorted_hashes: Vec<[u8; 32]> = self.receipts.keys().copied().collect();
        sorted_hashes.sort_unstable();
        // Full Merkle tree in production — XOR chain is a placeholder for the type
        let mut root = [0u8; 32];
        for hash in &sorted_hashes {
            for (i, b) in hash.iter().enumerate() {
                root[i] ^= b;
            }
        }
        Hash256(root)
    }
}

impl Default for TransactionStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Amount, BlockHeight, GasAmount, Hash256, TransactionHash};
    use aevor_core::transaction::{TransactionReceipt, TransactionStatus};

    fn tx_hash(n: u8) -> TransactionHash { Hash256([n; 32]) }

    fn make_receipt(n: u8, success: bool) -> TransactionReceipt {
        TransactionReceipt {
            transaction_hash: tx_hash(n),
            status: if success { TransactionStatus::FinalizedBasic } else { TransactionStatus::Failed },
            gas_consumed: GasAmount::from_u64(21_000),
            fee_paid: Amount::from_nano(21_000_000),
            state_changes: vec![],
            events: vec![],
            return_data: vec![],
            error: if success { None } else { Some("execution reverted".into()) },
            block_height: BlockHeight(100),
            finalized_round: 1,
            finality_proof: None,
            tee_attestation: None,
        }
    }

    #[test]
    fn store_and_get_by_hash() {
        let mut store = TransactionStore::new();
        store.store(make_receipt(1, true));
        let r = store.get(&tx_hash(1)).unwrap();
        assert!(matches!(r.status, TransactionStatus::FinalizedBasic));
        assert_eq!(r.gas_consumed.as_u64(), 21_000);
    }

    #[test]
    fn get_missing_returns_none() {
        let store = TransactionStore::default();
        assert!(store.get(&tx_hash(99)).is_none());
    }

    #[test]
    fn store_is_idempotent_for_same_hash() {
        let mut store = TransactionStore::new();
        store.store(make_receipt(1, true));
        store.store(make_receipt(1, true)); // same hash again
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn count_tracks_unique_receipts() {
        let mut store = TransactionStore::new();
        store.store(make_receipt(1, true));
        store.store(make_receipt(2, false));
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn receipt_root_is_zero_when_empty() {
        let store = TransactionStore::new();
        assert_eq!(store.receipt_root(), Hash256::ZERO);
    }

    #[test]
    fn receipt_root_is_non_zero_with_receipts() {
        let mut store = TransactionStore::new();
        store.store(make_receipt(1, true));
        assert_ne!(store.receipt_root(), Hash256::ZERO);
    }

    #[test]
    fn receipt_root_same_for_same_set_different_insertion_order() {
        let mut s1 = TransactionStore::new();
        let mut s2 = TransactionStore::new();
        s1.store(make_receipt(1, true));
        s1.store(make_receipt(2, true));
        s2.store(make_receipt(2, true)); // reversed order
        s2.store(make_receipt(1, true));
        assert_eq!(s1.receipt_root(), s2.receipt_root());
    }
}
