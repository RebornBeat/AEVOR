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
