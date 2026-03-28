//! Transaction rejection tracking.
//!
//! AEVOR does NOT roll back committed state. When a transaction fails (gas exhaustion,
//! privacy violation, execution error), it is **rejected** — it never commits to
//! finalized state. This module tracks why transactions were rejected, which is useful
//! for diagnostics, sender notification, and fee deduction decisions.
//!
//! The distinction is critical:
//! - `RejectionReason::OutOfGas` — execution ran out of gas; transaction rejected
//!   before any state was finalized. Gas fee is still charged.
//! - `RejectionReason::PrivacyViolation` — transaction attempted to access state
//!   it is not permitted to see; rejected immediately with no state change.
//! - `RejectionReason::ExecutionFailed` — VM execution encountered an error;
//!   transaction rejected with no state change.
//! - `RejectionReason::PreExecutionConflict` — conflict detected BEFORE execution;
//!   transaction never ran; sender should resubmit after the conflicting tx completes.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::TransactionHash;
use aevor_core::storage::StateRoot;

/// Reason a transaction was rejected (never committed to finalized state).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectionReason {
    /// VM execution failed (error in contract logic or runtime).
    ExecutionFailed,
    /// Pre-execution conflict detected by scheduler — transaction never ran.
    PreExecutionConflict,
    /// Transaction attempted a privacy boundary violation.
    PrivacyViolation,
    /// Transaction ran out of gas before completing execution.
    OutOfGas,
}

/// Record of a rejected transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectionRecord {
    /// Transaction that was rejected.
    pub transaction: TransactionHash,
    /// Reason for rejection.
    pub reason: RejectionReason,
    /// State root at the time of rejection (unchanged — rejection produces no state diff).
    pub state_root_unchanged: StateRoot,
}

impl RejectionRecord {
    /// Create a rejection record.
    pub fn new(transaction: TransactionHash, reason: RejectionReason, state_root: StateRoot) -> Self {
        Self { transaction, reason, state_root_unchanged: state_root }
    }
}

/// Tracks rejected transactions in a processing batch.
pub struct RejectionLog {
    records: Vec<RejectionRecord>,
}

impl RejectionLog {
    /// Create an empty rejection log.
    pub fn new() -> Self { Self { records: Vec::new() } }
    /// Record a rejection.
    pub fn record(&mut self, r: RejectionRecord) { self.records.push(r); }
    /// Number of rejected transactions.
    pub fn count(&self) -> usize { self.records.len() }
    /// Count rejections of a specific reason.
    pub fn count_reason(&self, reason: RejectionReason) -> usize {
        self.records.iter().filter(|r| r.reason == reason).count()
    }
    /// All records.
    pub fn records(&self) -> &[RejectionRecord] { &self.records }
}

impl Default for RejectionLog { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;
    use aevor_core::storage::MerkleRoot;

    fn tx(n: u8) -> TransactionHash { Hash256([n; 32]) }
    fn root() -> StateRoot { MerkleRoot::EMPTY }

    #[test]
    fn rejection_record_stores_fields() {
        let r = RejectionRecord::new(tx(1), RejectionReason::OutOfGas, root());
        assert_eq!(r.transaction, tx(1));
        assert_eq!(r.reason, RejectionReason::OutOfGas);
        assert_eq!(r.state_root_unchanged, root());
    }

    #[test]
    fn rejection_log_count_and_count_reason() {
        let mut log = RejectionLog::new();
        log.record(RejectionRecord::new(tx(1), RejectionReason::OutOfGas, root()));
        log.record(RejectionRecord::new(tx(2), RejectionReason::PreExecutionConflict, root()));
        log.record(RejectionRecord::new(tx(3), RejectionReason::OutOfGas, root()));
        assert_eq!(log.count(), 3);
        assert_eq!(log.count_reason(RejectionReason::OutOfGas), 2);
        assert_eq!(log.count_reason(RejectionReason::PreExecutionConflict), 1);
        assert_eq!(log.count_reason(RejectionReason::PrivacyViolation), 0);
    }

    #[test]
    fn rejection_log_empty_default() {
        let log = RejectionLog::default();
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn rejection_reasons_are_distinct() {
        assert_ne!(RejectionReason::OutOfGas, RejectionReason::PreExecutionConflict);
        assert_ne!(RejectionReason::ExecutionFailed, RejectionReason::PrivacyViolation);
    }

    #[test]
    fn pre_execution_conflict_represents_no_execution() {
        // Critical invariant: PreExecutionConflict means the transaction never ran.
        // The state root is unchanged because nothing executed.
        let r = RejectionRecord::new(tx(5), RejectionReason::PreExecutionConflict, root());
        assert_eq!(r.state_root_unchanged, MerkleRoot::EMPTY);
        // No state change occurred — root is the same as before.
    }

    #[test]
    fn rejection_log_records_all_reasons_across_batch() {
        let mut log = RejectionLog::new();
        log.record(RejectionRecord::new(tx(1), RejectionReason::PreExecutionConflict, root()));
        log.record(RejectionRecord::new(tx(2), RejectionReason::OutOfGas, root()));
        log.record(RejectionRecord::new(tx(3), RejectionReason::PrivacyViolation, root()));
        log.record(RejectionRecord::new(tx(4), RejectionReason::ExecutionFailed, root()));
        assert_eq!(log.count(), 4);
        assert_eq!(log.count_reason(RejectionReason::PreExecutionConflict), 1);
        assert_eq!(log.count_reason(RejectionReason::OutOfGas), 1);
        // All rejections leave the state root unchanged — no state was ever committed
        for record in log.records() {
            assert_eq!(record.state_root_unchanged, MerkleRoot::EMPTY);
        }
    }
}
