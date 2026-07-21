//! Composed execution pipeline — the first real cross-crate integration edge.
//!
//! Unlike the rest of `aevor-execution` (which operates on `aevor-core` types in
//! isolation), this module actually *calls into* the subsystem crates:
//!
//! - **`aevor-dag`** — real pre-execution conflict detection (`ConflictDetector`)
//!   producing accept/reject decisions (`PreExecutionBatch`). Conflicting
//!   transactions are **rejected before execution**; no state is speculatively
//!   applied and rolled back.
//! - **`aevor-crypto`** — real BLAKE3 content hashing of persisted object data.
//! - **`aevor-storage`** — real (in-memory) object persistence via `ObjectStore`
//!   backed by `MemoryBackend`.
//!
//! This composes the core write path: `transactions → DAG conflict rejection →
//! persist accepted writes → record rejections`. It is deliberately backend-
//! agnostic (swap `MemoryBackend` for the real RocksDB backend once wired) and
//! does not yet invoke the VM interpreter (which is not implemented — see the
//! stub-and-simulation register).

use aevor_core::primitives::{Address, ObjectId};
use aevor_core::privacy::PrivacyLevel;
use aevor_core::storage::MerkleRoot;
use aevor_crypto::hash::Blake3Hasher;
use aevor_dag::dependency::{ConflictDetector, ReadWriteSet};
use aevor_dag::speculative::{PreExecutionBatch, PreExecutionDecision};
use aevor_storage::backend::MemoryBackend;
use aevor_storage::objects::{ObjectMetadata, ObjectRecord, ObjectStore};
use aevor_vm::bytecode::BytecodeCodec;
use aevor_vm::vm::{AevorVm, VmConfig};

use aevor_core::primitives::GasAmount;

use crate::rollback::{RejectionLog, RejectionReason, RejectionRecord};

/// Summary of processing one batch of transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchOutcome {
    /// Transactions accepted (no pre-execution conflict) and executed.
    pub accepted: usize,
    /// Transactions rejected before execution due to a detected conflict.
    pub rejected: usize,
    /// Total objects written to storage across all accepted transactions.
    pub objects_written: usize,
}

/// Summary of processing a batch where accepted transactions execute bytecode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramOutcome {
    /// Transactions accepted (no conflict, program executed successfully).
    pub accepted: usize,
    /// Transactions rejected (pre-execution conflict or failed execution).
    pub rejected: usize,
    /// Total objects written to storage across all accepted transactions.
    pub objects_written: usize,
    /// Total gas consumed across all executed programs.
    pub total_gas_used: u64,
    /// Number of non-empty programs executed on the VM.
    pub programs_executed: usize,
    /// Object ids written by accepted transactions (for state-tree commitment).
    pub written_object_ids: Vec<ObjectId>,
    /// Per-accepted-transaction execution gas, keyed by transaction hash. Lets
    /// the caller settle fees against each sender individually rather than only
    /// in aggregate.
    pub accepted_tx_gas: Vec<(aevor_core::primitives::Hash256, u64)>,
}

/// A composed executor wiring DAG conflict detection, BLAKE3 hashing, and
/// object storage into a single write path.
pub struct ComposedExecutor {
    store: ObjectStore,
    rejections: RejectionLog,
    owner: Address,
    privacy: PrivacyLevel,
}

impl ComposedExecutor {
    /// Create a composed executor backed by in-memory storage.
    ///
    /// `owner` and `privacy` are applied to objects this executor writes.
    #[must_use]
    pub fn new(owner: Address, privacy: PrivacyLevel) -> Self {
        Self {
            store: ObjectStore::new(Box::new(MemoryBackend::new())),
            rejections: RejectionLog::new(),
            owner,
            privacy,
        }
    }

    /// Create a composed executor over a caller-supplied storage backend
    /// (e.g. a durable `LogBackend` in a running node, or `MemoryBackend` in
    /// tests). This is how durable persistence is wired into the pipeline.
    #[must_use]
    pub fn with_backend(
        backend: Box<dyn aevor_storage::backend::StorageBackend>,
        owner: Address,
        privacy: PrivacyLevel,
    ) -> Self {
        Self {
            store: ObjectStore::new(backend),
            rejections: RejectionLog::new(),
            owner,
            privacy,
        }
    }

    /// Process a batch of transactions described by their read/write sets.
    ///
    /// Each transaction is checked against all previously-accepted transactions
    /// in the batch. If it conflicts with any of them (via
    /// `ConflictDetector::conflict_type`), it is **rejected before execution**
    /// and recorded in the rejection log — its writes are never applied.
    /// Otherwise it is accepted and each of its written objects is persisted.
    ///
    /// # Errors
    /// Returns an error if a storage read or write fails.
    pub fn process_batch(&mut self, txs: &[ReadWriteSet]) -> crate::ExecutionResult<BatchOutcome> {
        let mut batch = PreExecutionBatch::default();
        let mut accepted: Vec<&ReadWriteSet> = Vec::new();
        let mut objects_written = 0usize;

        for tx in txs {
            let conflicts = accepted
                .iter()
                .any(|prior| ConflictDetector::conflict_type(prior, tx).is_some());

            if conflicts {
                batch.push(PreExecutionDecision::reject(
                    tx.transaction,
                    "pre-execution conflict detected",
                ));
                // Rejected transactions do not execute; the state root is unchanged.
                self.rejections.record(RejectionRecord::new(
                    tx.transaction,
                    RejectionReason::PreExecutionConflict,
                    MerkleRoot::EMPTY,
                ));
            } else {
                batch.push(PreExecutionDecision::accept(tx.transaction));
                accepted.push(tx);
                for object_id in &tx.writes {
                    self.write_object(*object_id, tx.transaction)?;
                    objects_written += 1;
                }
            }
        }

        Ok(BatchOutcome {
            accepted: batch.accepted_count(),
            rejected: batch.rejected_count(),
            objects_written,
        })
    }

    /// Persist (create or update) a single object written by `tx`.
    fn write_object(
        &mut self,
        id: ObjectId,
        tx: aevor_core::primitives::TransactionHash,
    ) -> crate::ExecutionResult<()> {
        // Next version = previous version + 1 (or 0 for a new object).
        let previous = self
            .store
            .get(&id)
            .map_err(|e| crate::ExecutionError::VmFailed(format!("storage read failed: {e}")))?;
        let version = previous.map_or(0, |record| record.metadata.version + 1);

        // Payload for this integration edge: the producing transaction hash.
        let data = tx.0.to_vec();

        // Real BLAKE3 content hash of the persisted data (wires aevor-crypto).
        let mut hasher = Blake3Hasher::new();
        hasher.update(&data);
        let content_hash = hasher.finalize().0;

        let record = ObjectRecord {
            metadata: ObjectMetadata {
                id,
                owner: self.owner,
                privacy_level: self.privacy,
                version,
                content_hash,
                size_bytes: data.len(),
            },
            data,
        };

        self.store
            .put(&record)
            .map_err(|e| crate::ExecutionError::VmFailed(format!("storage write failed: {e}")))?;
        Ok(())
    }

    /// Number of transactions rejected so far across all processed batches.
    #[must_use]
    pub fn rejection_count(&self) -> usize {
        self.rejections.count()
    }

    /// Fetch a persisted object by id, if present.
    ///
    /// # Errors
    /// Returns an error if the storage read fails.
    pub fn object(&self, id: &ObjectId) -> crate::ExecutionResult<Option<ObjectRecord>> {
        self.store
            .get(id)
            .map_err(|e| crate::ExecutionError::VmFailed(format!("storage read failed: {e}")))
    }

    /// Enumerate all committed objects as `(id, data)`.
    ///
    /// Used to rebuild the authenticated state tree on node startup, and for
    /// state sync when a validator joins.
    ///
    /// # Errors
    /// Returns an error if the storage scan fails.
    pub fn committed_objects(&self) -> crate::ExecutionResult<Vec<(ObjectId, Vec<u8>)>> {
        let records = self
            .store
            .all_records()
            .map_err(|e| crate::ExecutionError::VmFailed(format!("storage scan failed: {e}")))?;
        Ok(records
            .into_iter()
            .map(|r| (r.metadata.id, r.data))
            .collect())
    }

    /// Process a batch where each accepted transaction also **executes a
    /// bytecode program on the VM** before its writes are persisted.
    ///
    /// The full canonical path: DAG conflict detection rejects conflicting
    /// transactions before execution; each surviving transaction's bytecode is
    /// decoded and run on `AevorVm`; if execution **fails** (out of gas, abort,
    /// etc.) the transaction is rejected and **no state is committed** (never a
    /// partial commit); only on a verified successful execution are its writes
    /// persisted. Transactions with empty bytecode are treated as pure
    /// state-writes (no VM step).
    ///
    /// # Errors
    /// Returns an error if bytecode decoding hits an internal error or a storage
    /// write fails. (Normal execution failures are recorded as rejections, not
    /// returned as errors.)
    pub fn process_program_batch(
        &mut self,
        txs: &[(ReadWriteSet, Vec<u8>)],
        gas_limit_per_tx: GasAmount,
    ) -> crate::ExecutionResult<ProgramOutcome> {
        // PASS 1 (sequential, deterministic): pre-execution conflict rejection.
        // A transaction conflicts with the accepted set iff any of its writes
        // touches an accepted write or read, or any of its reads touches an
        // accepted write (the exact `ConflictDetector` relation, aggregated).
        // Two `HashSet`s make this O(total set size) instead of the previous
        // O(n²) pairwise scan — the source of the superlinear slowdown on large
        // batches. Order is preserved, so conflict *winners* are unchanged.
        use rayon::prelude::*;
        use std::collections::HashSet;

        let mut accepted_writes: HashSet<ObjectId> = HashSet::new();
        let mut accepted_reads: HashSet<ObjectId> = HashSet::new();
        let mut accepted: Vec<&(ReadWriteSet, Vec<u8>)> = Vec::new();
        let mut conflict_rejected = 0usize;

        for item in txs {
            let rw = &item.0;
            let conflicts = rw
                .writes
                .iter()
                .any(|w| accepted_writes.contains(w) || accepted_reads.contains(w))
                || rw.reads.iter().any(|r| accepted_writes.contains(r));
            if conflicts {
                conflict_rejected += 1;
                self.rejections.record(RejectionRecord::new(
                    rw.transaction,
                    RejectionReason::PreExecutionConflict,
                    MerkleRoot::EMPTY,
                ));
            } else {
                for w in &rw.writes {
                    accepted_writes.insert(*w);
                }
                for r in &rw.reads {
                    accepted_reads.insert(*r);
                }
                accepted.push(item);
            }
        }

        // PASS 2a (sequential): decode each accepted program's bytecode. Empty
        // bytecode = pure state-write (no program). A decode error fails the
        // batch (as before).
        let programs: Vec<Option<_>> = accepted
            .iter()
            .map(|(_, bytecode)| {
                if bytecode.is_empty() {
                    Ok(None)
                } else {
                    BytecodeCodec::decode(bytecode)
                        .map(Some)
                        .map_err(|e| crate::ExecutionError::VmFailed(format!("bytecode decode: {e}")))
                }
            })
            .collect::<crate::ExecutionResult<Vec<_>>>()?;

        // PASS 2b (PARALLEL): execute the accepted programs. They have disjoint
        // read/write sets by construction, so execution is order-independent and
        // the result is deterministic; each task uses its own VM. This is the
        // micro-DAG's independent set actually running in parallel.
        let gas = gas_limit_per_tx;
        let exec: Vec<(bool, bool, u64)> = programs
            .par_iter()
            .map(|prog| match prog {
                None => (true, false, 0u64),
                Some(program) => {
                    let vm = AevorVm::new(VmConfig::default());
                    match vm.execute(program, gas) {
                        Ok(e) => (true, true, e.gas_used.0),
                        Err(_) => (false, false, 0),
                    }
                }
            })
            .collect();

        // PASS 3 (sequential, in accepted order): apply results deterministically
        // — persist writes for successes; record execution failures as rejections.
        let mut outcome = ProgramOutcome {
            accepted: 0,
            rejected: conflict_rejected,
            objects_written: 0,
            total_gas_used: 0,
            programs_executed: 0,
            written_object_ids: Vec::new(),
            accepted_tx_gas: Vec::new(),
        };

        for ((rw, _), (ok, executed, gas_used)) in accepted.iter().zip(exec.iter()) {
            if *ok {
                outcome.accepted += 1;
                outcome.total_gas_used += *gas_used;
                outcome.accepted_tx_gas.push((rw.transaction, *gas_used));
                if *executed {
                    outcome.programs_executed += 1;
                }
                for object_id in &rw.writes {
                    self.write_object(*object_id, rw.transaction)?;
                    outcome.objects_written += 1;
                    outcome.written_object_ids.push(*object_id);
                }
            } else {
                outcome.rejected += 1;
                self.rejections.record(RejectionRecord::new(
                    rw.transaction,
                    RejectionReason::ExecutionFailed,
                    MerkleRoot::EMPTY,
                ));
            }
        }

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, Hash256, ObjectId, TransactionHash};

    fn tx(n: u8) -> TransactionHash {
        Hash256([n; 32])
    }

    fn obj(n: u8) -> ObjectId {
        ObjectId(Hash256([n; 32]))
    }

    fn rw(t: u8, reads: &[u8], writes: &[u8]) -> ReadWriteSet {
        ReadWriteSet {
            transaction: tx(t),
            reads: reads.iter().map(|&n| obj(n)).collect(),
            writes: writes.iter().map(|&n| obj(n)).collect(),
        }
    }

    fn executor() -> ComposedExecutor {
        ComposedExecutor::new(Address::from_bytes([1u8; 32]), PrivacyLevel::Public)
    }

    #[test]
    fn disjoint_transactions_all_accepted_and_persisted() {
        let mut exec = executor();
        // Three transactions writing disjoint objects — no conflicts.
        let batch = vec![
            rw(1, &[], &[10]),
            rw(2, &[], &[20]),
            rw(3, &[], &[30]),
        ];
        let outcome = exec.process_batch(&batch).unwrap();
        assert_eq!(outcome.accepted, 3);
        assert_eq!(outcome.rejected, 0);
        assert_eq!(outcome.objects_written, 3);
        // Each written object is retrievable from storage.
        assert!(exec.object(&obj(10)).unwrap().is_some());
        assert!(exec.object(&obj(20)).unwrap().is_some());
        assert!(exec.object(&obj(30)).unwrap().is_some());
    }

    #[test]
    fn write_write_conflict_rejects_second_transaction() {
        let mut exec = executor();
        // Both write object 10 → the second conflicts and is rejected.
        let batch = vec![rw(1, &[], &[10]), rw(2, &[], &[10])];
        let outcome = exec.process_batch(&batch).unwrap();
        assert_eq!(outcome.accepted, 1);
        assert_eq!(outcome.rejected, 1);
        assert_eq!(outcome.objects_written, 1);
        assert_eq!(exec.rejection_count(), 1);
    }

    #[test]
    fn read_write_conflict_is_detected() {
        let mut exec = executor();
        // tx1 writes obj 5; tx2 reads obj 5 → read-after-write conflict → tx2 rejected.
        let batch = vec![rw(1, &[], &[5]), rw(2, &[5], &[])];
        let outcome = exec.process_batch(&batch).unwrap();
        assert_eq!(outcome.accepted, 1);
        assert_eq!(outcome.rejected, 1);
    }

    #[test]
    fn read_only_transactions_never_conflict() {
        let mut exec = executor();
        // Many transactions reading the same object — read-read sharing is safe.
        let batch = vec![rw(1, &[7], &[]), rw(2, &[7], &[]), rw(3, &[7], &[])];
        let outcome = exec.process_batch(&batch).unwrap();
        assert_eq!(outcome.accepted, 3);
        assert_eq!(outcome.rejected, 0);
        assert_eq!(outcome.objects_written, 0);
    }

    #[test]
    fn updating_same_object_across_batches_increments_version() {
        let mut exec = executor();
        exec.process_batch(&[rw(1, &[], &[42])]).unwrap();
        let v0 = exec.object(&obj(42)).unwrap().unwrap().metadata.version;
        exec.process_batch(&[rw(2, &[], &[42])]).unwrap();
        let v1 = exec.object(&obj(42)).unwrap().unwrap().metadata.version;
        assert_eq!(v0, 0);
        assert_eq!(v1, 1);
    }

    #[test]
    fn content_hash_is_real_blake3_of_data() {
        let mut exec = executor();
        exec.process_batch(&[rw(9, &[], &[99])]).unwrap();
        let record = exec.object(&obj(99)).unwrap().unwrap();
        // Recompute the expected BLAKE3 hash of the stored data.
        let mut hasher = Blake3Hasher::new();
        hasher.update(&record.data);
        let expected = hasher.finalize().0;
        assert_eq!(record.metadata.content_hash, expected);
    }

    #[test]
    fn program_batch_executes_bytecode_and_persists() {
        use aevor_vm::bytecode::BytecodeCodec;
        use aevor_vm::instructions::Instruction::{Add, Ld};
        let mut exec = executor();
        // A valid program: (2 + 3). Two disjoint transactions.
        let prog = BytecodeCodec::encode(&[Ld(2), Ld(3), Add]);
        let batch = vec![
            (rw(1, &[], &[10]), prog.clone()),
            (rw(2, &[], &[20]), prog.clone()),
        ];
        let out = exec.process_program_batch(&batch, GasAmount(10_000)).unwrap();
        assert_eq!(out.accepted, 2);
        assert_eq!(out.rejected, 0);
        assert_eq!(out.programs_executed, 2);
        assert_eq!(out.objects_written, 2);
        assert!(out.total_gas_used > 0);
        assert!(exec.object(&obj(10)).unwrap().is_some());
    }

    #[test]
    fn failed_execution_rejects_and_commits_no_state() {
        use aevor_vm::bytecode::BytecodeCodec;
        use aevor_vm::instructions::Instruction::{Div, Ld};
        let mut exec = executor();
        // Division by zero → execution fails → transaction rejected, no write.
        let bad = BytecodeCodec::encode(&[Ld(1), Ld(0), Div]);
        let out = exec
            .process_program_batch(&[(rw(1, &[], &[10]), bad)], GasAmount(10_000))
            .unwrap();
        assert_eq!(out.accepted, 0);
        assert_eq!(out.rejected, 1);
        assert_eq!(out.objects_written, 0);
        // No state committed for the failed transaction.
        assert!(exec.object(&obj(10)).unwrap().is_none());
    }

    #[test]
    fn program_batch_rejects_conflicts_before_execution() {
        use aevor_vm::bytecode::BytecodeCodec;
        use aevor_vm::instructions::Instruction::{Add, Ld};
        let mut exec = executor();
        let prog = BytecodeCodec::encode(&[Ld(1), Ld(1), Add]);
        // Both write object 10 → second conflicts, rejected before executing.
        let batch = vec![
            (rw(1, &[], &[10]), prog.clone()),
            (rw(2, &[], &[10]), prog.clone()),
        ];
        let out = exec.process_program_batch(&batch, GasAmount(10_000)).unwrap();
        assert_eq!(out.accepted, 1);
        assert_eq!(out.rejected, 1);
        assert_eq!(out.programs_executed, 1); // only the accepted one ran
    }

    #[test]
    fn out_of_gas_execution_is_rejected() {
        use aevor_vm::bytecode::BytecodeCodec;
        use aevor_vm::instructions::Instruction::Alloc;
        let mut exec = executor();
        // Alloc costs 300 gas; a tiny limit cannot afford it → execution fails.
        let prog = BytecodeCodec::encode(&[Alloc]);
        let out = exec
            .process_program_batch(&[(rw(1, &[], &[10]), prog)], GasAmount(10))
            .unwrap();
        assert_eq!(out.rejected, 1);
        assert_eq!(out.accepted, 0);
    }
}
