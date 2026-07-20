//! Object dependency graph for parallel execution planning.
//!
//! The `ConflictDetector` and `DependencyAnalyzer` implement AEVOR's core
//! pre-execution conflict resolution model:
//!
//! 1. **Before any transaction executes**, its read/write set is submitted.
//! 2. `ConflictDetector` identifies all conflict types (WAW, RAW, WAR).
//! 3. `DependencyAnalyzer` builds the dependency graph.
//! 4. The scheduler **rejects** conflicting transactions — they never execute.
//! 5. No state is ever unwound; finalized state is immutable.
//!
//! Transactions that conflict are returned to their senders, who may resubmit
//! after the dependency resolves. This is a sender-side decision, not an
//! automatic infrastructure retry.

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
        let mut edges: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
        let mut reverse_edges: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();

        // Directional dependency edges: for a conflicting pair (i, j) with i < j,
        // the later transaction j depends on the earlier transaction i. Edges
        // point only forward in submission order, so the graph is acyclic —
        // matching AEVOR's rule that conflicts are resolved by submission order
        // (the earlier transaction wins; the later one waits or is rejected).
        for i in 0..read_write_sets.len() {
            for j in (i + 1)..read_write_sets.len() {
                if ConflictDetector::conflict_type(&read_write_sets[i], &read_write_sets[j]).is_some() {
                    edges.entry(i).or_default().push(j); // j depends on i
                    reverse_edges.entry(j).or_default().push(i); // j's dependency: i
                }
            }
        }

        let topological_order = Self::kahn_topological_order(vertices.len(), &edges, &reverse_edges);
        DependencyGraph { vertices, edges, reverse_edges, topological_order }
    }

    /// Kahn's algorithm: produce a dependency-respecting linear execution order.
    ///
    /// Ready vertices (no remaining dependencies) are emitted in ascending index
    /// order, so the result is deterministic.
    fn kahn_topological_order(
        n: usize,
        edges: &std::collections::HashMap<usize, Vec<usize>>,
        reverse_edges: &std::collections::HashMap<usize, Vec<usize>>,
    ) -> Vec<usize> {
        let mut in_degree: Vec<usize> = (0..n)
            .map(|v| reverse_edges.get(&v).map_or(0, Vec::len))
            .collect();
        let mut ready: std::collections::BTreeSet<usize> =
            (0..n).filter(|v| in_degree[*v] == 0).collect();
        let mut order = Vec::with_capacity(n);
        while let Some(&v) = ready.iter().next() {
            ready.remove(&v);
            order.push(v);
            if let Some(successors) = edges.get(&v) {
                for &w in successors {
                    in_degree[w] -= 1;
                    if in_degree[w] == 0 {
                        ready.insert(w);
                    }
                }
            }
        }
        order
    }

    /// Compute parallel execution levels ("waves").
    ///
    /// Each inner vector is a set of transaction indices whose dependencies are
    /// all satisfied by earlier levels, so every transaction within a level may
    /// execute **concurrently**. This is AEVOR's parallel execution model:
    /// independent transactions run in parallel; dependent ones are ordered
    /// across successive levels. An empty graph yields no levels; fully
    /// independent transactions yield a single level.
    #[must_use]
    pub fn parallel_execution_levels(graph: &DependencyGraph) -> Vec<Vec<usize>> {
        let n = graph.vertices.len();
        let mut in_degree: Vec<usize> = (0..n)
            .map(|v| graph.reverse_edges.get(&v).map_or(0, Vec::len))
            .collect();
        let mut current: Vec<usize> = (0..n).filter(|v| in_degree[*v] == 0).collect();
        current.sort_unstable();
        let mut levels = Vec::new();
        while !current.is_empty() {
            let mut next: Vec<usize> = Vec::new();
            for &v in &current {
                if let Some(successors) = graph.edges.get(&v) {
                    for &w in successors {
                        in_degree[w] -= 1;
                        if in_degree[w] == 0 {
                            next.push(w);
                        }
                    }
                }
            }
            next.sort_unstable();
            levels.push(current);
            current = next;
        }
        levels
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

    #[test]
    fn conflict_detector_returns_none_for_independent_transactions() {
        // Independent transactions have no conflict → both are accepted for parallel execution.
        let a = rw(1, &[1, 2], &[5]);
        let b = rw(2, &[3, 4], &[6]);
        assert!(ConflictDetector::conflict_type(&a, &b).is_none());
        assert!(ConflictDetector::conflict_type(&b, &a).is_none());
    }

    #[test]
    fn conflicting_transaction_is_rejected_not_executed() {
        // ARCHITECTURE INVARIANT: ConflictDetector identifies conflicts BEFORE execution.
        // If conflict_type returns Some(_), the losing transaction is rejected by the scheduler.
        // No execution occurs for the rejected transaction.
        let writer = rw(1, &[], &[42]); // writes obj 42
        let also_writer = rw(2, &[], &[42]); // also writes obj 42 — conflict!
        let conflict = ConflictDetector::conflict_type(&writer, &also_writer);
        assert_eq!(conflict, Some(DependencyType::WriteAfterWrite));
        // Detection happened pre-execution. `also_writer` would be rejected.
        // No state changed. Sender of tx 2 may resubmit after tx 1 finalizes.
    }

    #[test]
    fn dependency_graph_reverse_edges_track_dependents() {
        // tx 1 writes obj 10, tx 2 reads obj 10 → tx 2 depends on tx 1
        let sets = vec![rw(1, &[], &[10]), rw(2, &[10], &[])];
        let graph = DependencyAnalyzer::analyze(&sets);
        // reverse_edges[1] means "vertex 1 (tx 2) must wait for vertex 0 (tx 1)"
        assert!(graph.reverse_edges.contains_key(&1));
    }

    #[test]
    fn read_read_sharing_never_conflicts() {
        // Multiple transactions reading the same object is always safe for parallel execution.
        let a = rw(1, &[10, 20], &[]);
        let b = rw(2, &[10, 30], &[]); // shares obj 10 read
        let c = rw(3, &[20], &[]);     // shares obj 20 read
        assert!(ConflictDetector::conflict_type(&a, &b).is_none());
        assert!(ConflictDetector::conflict_type(&a, &c).is_none());
        assert!(ConflictDetector::conflict_type(&b, &c).is_none());
    }

    #[test]
    fn topological_order_respects_dependencies() {
        // tx0 writes obj5; tx1 reads obj5 → tx1 depends on tx0.
        let graph = DependencyAnalyzer::analyze(&[rw(1, &[], &[5]), rw(2, &[5], &[])]);
        let pos0 = graph.topological_order.iter().position(|&v| v == 0).unwrap();
        let pos1 = graph.topological_order.iter().position(|&v| v == 1).unwrap();
        assert!(pos0 < pos1, "dependency (0 before 1) must be respected");
        assert_eq!(graph.topological_order.len(), 2);
    }

    #[test]
    fn topological_order_is_complete_for_chain() {
        let graph = DependencyAnalyzer::analyze(&[
            rw(1, &[], &[10]),
            rw(2, &[10], &[20]),
            rw(3, &[20], &[]),
        ]);
        assert_eq!(graph.topological_order, vec![0, 1, 2]);
    }

    #[test]
    fn independent_transactions_form_single_parallel_level() {
        let graph = DependencyAnalyzer::analyze(&[
            rw(1, &[], &[1]),
            rw(2, &[], &[2]),
            rw(3, &[], &[3]),
        ]);
        let levels = DependencyAnalyzer::parallel_execution_levels(&graph);
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], vec![0, 1, 2]);
    }

    #[test]
    fn dependency_chain_forms_sequential_levels() {
        let graph = DependencyAnalyzer::analyze(&[
            rw(1, &[], &[10]),
            rw(2, &[10], &[20]),
            rw(3, &[20], &[]),
        ]);
        let levels = DependencyAnalyzer::parallel_execution_levels(&graph);
        assert_eq!(levels, vec![vec![0], vec![1], vec![2]]);
    }

    #[test]
    fn mixed_graph_groups_independent_then_dependent() {
        // 0 and 1 independent; 2 depends on both.
        let graph = DependencyAnalyzer::analyze(&[
            rw(1, &[], &[100]),
            rw(2, &[], &[200]),
            rw(3, &[100, 200], &[]),
        ]);
        let levels = DependencyAnalyzer::parallel_execution_levels(&graph);
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], vec![0, 1]);
        assert_eq!(levels[1], vec![2]);
    }
}
