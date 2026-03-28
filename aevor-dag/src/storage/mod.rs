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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }
    fn bh(n: u8) -> BlockHash { Hash256([n; 32]) }

    fn entry(n: u8) -> DagStorageEntry {
        DagStorageEntry { transaction: tx(n), parents: vec![], included_in_block: None, finalized: false }
    }

    #[test]
    fn dag_store_insert_and_get() {
        let mut store = DagStore::new();
        store.insert(entry(1));
        assert!(store.get(&tx(1)).is_some());
        assert_eq!(store.entry_count(), 1);
    }

    #[test]
    fn dag_store_get_missing_returns_none() {
        let store = DagStore::default();
        assert!(store.get(&tx(99)).is_none());
    }

    #[test]
    fn dag_storage_entry_with_block_reference() {
        let e = DagStorageEntry { transaction: tx(2), parents: vec![tx(1)], included_in_block: Some(bh(5)), finalized: true };
        assert!(e.included_in_block.is_some());
        assert!(e.finalized);
        assert_eq!(e.parents.len(), 1);
    }

    #[test]
    fn dag_store_multiple_entries() {
        let mut store = DagStore::new();
        for i in 0..5 { store.insert(entry(i)); }
        assert_eq!(store.entry_count(), 5);
    }
}
