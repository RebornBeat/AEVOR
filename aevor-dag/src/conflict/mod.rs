//! Conflict detection and resolution in the DAG.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{ObjectId, TransactionHash};
use aevor_core::execution::DependencyType;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictType {
    WriteWrite,
    ReadWrite,
    WriteRead,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteWriteConflict {
    pub tx_a: TransactionHash,
    pub tx_b: TransactionHash,
    pub object: ObjectId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadWriteConflict {
    pub reader: TransactionHash,
    pub writer: TransactionHash,
    pub object: ObjectId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictResolution {
    pub conflict_type: ConflictType,
    pub winner: TransactionHash,
    pub loser: TransactionHash,
    pub reason: String,
}

/// A conflict edge between two transactions, annotated with its dependency type.
///
/// `DependencyType` classifies whether the conflict is a raw data dependency,
/// an object-ownership dependency, or an ordering dependency. This is used by
/// the scheduler to decide which conflicts require sequential execution vs.
/// which can be resolved via MVCC retry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictEdge {
    /// Transaction that writes first.
    pub writer: TransactionHash,
    /// Transaction that conflicts with the write.
    pub dependent: TransactionHash,
    /// Object that caused the conflict.
    pub object: ObjectId,
    /// Classification of this dependency.
    pub dependency_type: DependencyType,
}

impl ConflictEdge {
    /// Create a new conflict edge.
    pub fn new(
        writer: TransactionHash,
        dependent: TransactionHash,
        object: ObjectId,
        dependency_type: DependencyType,
    ) -> Self {
        Self { writer, dependent, object, dependency_type }
    }

    /// Returns `true` if this conflict requires sequential ordering.
    pub fn requires_sequential(&self) -> bool {
        matches!(self.dependency_type, DependencyType::WriteAfterWrite)
    }
}

pub struct ConflictResolver;

impl ConflictResolver {
    pub fn resolve(
        conflict_type: ConflictType,
        tx_a: TransactionHash,
        tx_b: TransactionHash,
    ) -> ConflictResolution {
        // Deterministic: lower hash wins.
        let (winner, loser) = if tx_a.0 <= tx_b.0 { (tx_a, tx_b) } else { (tx_b, tx_a) };
        ConflictResolution {
            conflict_type,
            winner,
            loser,
            reason: "deterministic ordering by hash".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, ObjectId, TransactionHash};
    use aevor_core::execution::DependencyType;

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }
    fn obj(n: u8) -> ObjectId { ObjectId(Hash256([n; 32])) }

    #[test]
    fn conflict_edge_write_after_write_requires_sequential() {
        let edge = ConflictEdge::new(tx(1), tx(2), obj(5), DependencyType::WriteAfterWrite);
        assert!(edge.requires_sequential());
    }

    #[test]
    fn conflict_edge_read_after_write_does_not_require_sequential() {
        let edge = ConflictEdge::new(tx(1), tx(2), obj(5), DependencyType::ReadAfterWrite);
        assert!(!edge.requires_sequential());
    }

    #[test]
    fn conflict_resolver_lower_hash_wins() {
        let resolution = ConflictResolver::resolve(ConflictType::WriteWrite, tx(5), tx(1));
        assert_eq!(resolution.winner, tx(1));
        assert_eq!(resolution.loser, tx(5));
    }

    #[test]
    fn conflict_resolver_equal_hashes_first_wins() {
        let resolution = ConflictResolver::resolve(ConflictType::ReadWrite, tx(3), tx(3));
        assert_eq!(resolution.winner, tx(3));
        assert_eq!(resolution.loser, tx(3));
    }

    #[test]
    fn conflict_resolver_preserves_conflict_type() {
        let resolution = ConflictResolver::resolve(ConflictType::WriteRead, tx(2), tx(1));
        assert_eq!(resolution.conflict_type, ConflictType::WriteRead);
    }

    #[test]
    fn write_write_conflict_stores_txs_and_object() {
        let c = WriteWriteConflict { tx_a: tx(1), tx_b: tx(2), object: obj(9) };
        assert_eq!(c.object, obj(9));
    }

    #[test]
    fn read_write_conflict_stores_reader_and_writer() {
        let c = ReadWriteConflict { reader: tx(1), writer: tx(2), object: obj(3) };
        assert_eq!(c.reader, tx(1));
        assert_eq!(c.writer, tx(2));
    }
}
