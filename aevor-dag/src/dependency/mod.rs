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
