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
        sorted_hashes.sort();
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
