//! DAG persistence: storing and retrieving DAG entries.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{BlockHash, TransactionHash};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DagStorageEntry {
    pub transaction: TransactionHash,
    pub parents: Vec<TransactionHash>,
    pub included_in_block: Option<BlockHash>,
    pub finalized: bool,
}

pub struct DagStore {
    entries: std::collections::HashMap<[u8; 32], DagStorageEntry>,
}

impl DagStore {
    pub fn new() -> Self { Self { entries: std::collections::HashMap::new() } }

    pub fn insert(&mut self, entry: DagStorageEntry) {
        self.entries.insert(entry.transaction.0, entry);
    }

    pub fn get(&self, tx: &TransactionHash) -> Option<&DagStorageEntry> {
        self.entries.get(&tx.0)
    }

    pub fn entry_count(&self) -> usize { self.entries.len() }
}

impl Default for DagStore {
    fn default() -> Self { Self::new() }
}
