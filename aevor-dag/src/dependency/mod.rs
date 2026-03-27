//! Object dependency graph for parallel execution planning.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{ObjectId, TransactionHash};
use aevor_core::execution::DependencyType;
pub use aevor_core::coordination::DependencyGraph;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyNode {
    pub transaction: TransactionHash,
    pub depth: usize,
}

pub type DepEdge = aevor_core::execution::ObjectDependency;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadWriteSet {
    pub transaction: TransactionHash,
    pub reads: Vec<ObjectId>,
    pub writes: Vec<ObjectId>,
}

pub struct ConflictDetector;

impl ConflictDetector {
    pub fn conflict_type(a: &ReadWriteSet, b: &ReadWriteSet) -> Option<DependencyType> {
        for w in &a.writes {
            if b.writes.contains(w) { return Some(DependencyType::WriteAfterWrite); }
            if b.reads.contains(w) { return Some(DependencyType::ReadAfterWrite); }
        }
        for r in &a.reads {
            if b.writes.contains(r) { return Some(DependencyType::WriteAfterRead); }
        }
        None
    }
}

pub struct DependencyAnalyzer;

impl DependencyAnalyzer {
    pub fn analyze(read_write_sets: &[ReadWriteSet]) -> DependencyGraph {
        let vertices: Vec<TransactionHash> = read_write_sets.iter().map(|rw| rw.transaction).collect();
        let mut edges = std::collections::HashMap::new();
        let mut reverse_edges = std::collections::HashMap::new();

        for (i, a) in read_write_sets.iter().enumerate() {
            for (j, b) in read_write_sets.iter().enumerate() {
                if i == j { continue; }
                if ConflictDetector::conflict_type(a, b).is_some() {
                    edges.entry(i).or_insert_with(Vec::new).push(j);
                    reverse_edges.entry(j).or_insert_with(Vec::new).push(i);
                }
            }
        }

        let topo: Vec<usize> = (0..vertices.len()).collect(); // Simplified topo sort
        DependencyGraph { vertices, edges, reverse_edges, topological_order: topo }
    }
}

pub type ObjectDependencyGraph = DependencyGraph;

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Hash256, ObjectId, TransactionHash};
    use aevor_core::execution::DependencyType;

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }
    fn obj(n: u8) -> ObjectId { ObjectId(Hash256([n; 32])) }

    fn rw(tx_byte: u8, reads: &[u8], writes: &[u8]) -> ReadWriteSet {
        ReadWriteSet {
            transaction: tx(tx_byte),
            reads: reads.iter().map(|&n| obj(n)).collect(),
            writes: writes.iter().map(|&n| obj(n)).collect(),
        }
    }

    #[test]
    fn conflict_write_after_write_detected() {
        let a = rw(1, &[], &[10]);
        let b = rw(2, &[], &[10]); // both write obj 10
        assert_eq!(
            ConflictDetector::conflict_type(&a, &b),
            Some(DependencyType::WriteAfterWrite)
        );
    }

    #[test]
    fn conflict_read_after_write_detected() {
        let a = rw(1, &[], &[10]); // a writes obj 10
        let b = rw(2, &[10], &[]); // b reads obj 10
        assert_eq!(
            ConflictDetector::conflict_type(&a, &b),
            Some(DependencyType::ReadAfterWrite)
        );
    }

    #[test]
    fn conflict_write_after_read_detected() {
        let a = rw(1, &[10], &[]); // a reads obj 10
        let b = rw(2, &[], &[10]); // b writes obj 10
        assert_eq!(
            ConflictDetector::conflict_type(&a, &b),
            Some(DependencyType::WriteAfterRead)
        );
    }

    #[test]
    fn no_conflict_for_disjoint_sets() {
        let a = rw(1, &[1], &[2]);
        let b = rw(2, &[3], &[4]);
        assert_eq!(ConflictDetector::conflict_type(&a, &b), None);
    }

    #[test]
    fn no_conflict_for_read_read_sharing() {
        let a = rw(1, &[10], &[]);
        let b = rw(2, &[10], &[]); // both only read obj 10
        assert_eq!(ConflictDetector::conflict_type(&a, &b), None);
    }

    #[test]
    fn analyzer_produces_graph_with_correct_vertex_count() {
        let sets = vec![rw(1, &[1], &[2]), rw(2, &[3], &[4])];
        let graph = DependencyAnalyzer::analyze(&sets);
        assert_eq!(graph.vertices.len(), 2);
    }

    #[test]
    fn analyzer_detects_edge_for_conflicting_transactions() {
        // tx 1 writes obj 10, tx 2 reads obj 10 → edge from 1 to 2
        let sets = vec![rw(1, &[], &[10]), rw(2, &[10], &[])];
        let graph = DependencyAnalyzer::analyze(&sets);
        // vertex 0 (tx 1) should have an edge to vertex 1 (tx 2)
        assert!(graph.edges.contains_key(&0));
    }

    #[test]
    fn analyzer_no_edges_for_independent_transactions() {
        let sets = vec![rw(1, &[1], &[2]), rw(2, &[3], &[4])];
        let graph = DependencyAnalyzer::analyze(&sets);
        assert!(graph.edges.is_empty());
    }
}
