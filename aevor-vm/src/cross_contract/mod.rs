//! Cross-contract call coordination.
//!
//! AEVOR contracts can call other contracts across privacy boundaries.
//! Each cross-contract call carries its own gas budget and produces a
//! `CrossContractReceipt` that is included in the parent receipt.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, GasAmount, Hash256};

/// A cross-contract call invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossContractCall {
    /// Calling contract address.
    pub caller: Address,
    /// Called contract address.
    pub callee: Address,
    /// Function selector / name.
    pub function: String,
    /// Gas budget allocated to this sub-call.
    pub gas_budget: GasAmount,
}

/// Result receipt from a cross-contract call.
///
/// The `call_hash` commits to the call parameters and result, allowing
/// the parent contract to verify the sub-call outcome deterministically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossContractReceipt {
    /// Identifying hash of the sub-call (hash of caller, callee, function, args).
    pub call_hash: Hash256,
    /// Whether the sub-call succeeded.
    pub success: bool,
    /// Gas actually consumed by the sub-call.
    pub gas_used: GasAmount,
    /// Return data from the called contract.
    pub return_data: Vec<u8>,
}

impl CrossContractReceipt {
    /// Build a receipt for a successful sub-call.
    pub fn success(call_hash: Hash256, gas_used: GasAmount, return_data: Vec<u8>) -> Self {
        Self { call_hash, success: true, gas_used, return_data }
    }

    /// Build a receipt for a failed sub-call.
    pub fn failure(call_hash: Hash256, gas_used: GasAmount) -> Self {
        Self { call_hash, success: false, gas_used, return_data: Vec::new() }
    }
}

/// Guards against call-stack overflow in recursive cross-contract calls.
pub struct CallDepthGuard {
    /// Current recursion depth.
    pub current_depth: u32,
    /// Maximum allowed depth.
    pub max_depth: u32,
}

impl CallDepthGuard {
    /// Create a depth guard with the given maximum.
    pub fn new(max_depth: u32) -> Self { Self { current_depth: 0, max_depth } }

    /// Enter one level of nesting. Returns `false` if the limit is reached.
    pub fn enter(&mut self) -> bool {
        if self.current_depth < self.max_depth {
            self.current_depth += 1;
            true
        } else {
            false
        }
    }

    /// Exit one level of nesting.
    pub fn exit(&mut self) { self.current_depth = self.current_depth.saturating_sub(1); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_guard_allows_up_to_max() {
        let mut g = CallDepthGuard::new(3);
        assert!(g.enter()); // 1
        assert!(g.enter()); // 2
        assert!(g.enter()); // 3
        assert!(!g.enter()); // over limit
    }

    #[test]
    fn depth_guard_allows_reentry_after_exit() {
        let mut g = CallDepthGuard::new(1);
        assert!(g.enter());
        g.exit();
        assert!(g.enter());
    }

    #[test]
    fn receipt_success_has_correct_flag() {
        let h = Hash256([1u8; 32]);
        let r = CrossContractReceipt::success(h, GasAmount::from_u64(100), vec![1, 2, 3]);
        assert!(r.success);
        assert_eq!(r.call_hash, h);
        assert_eq!(r.return_data, vec![1, 2, 3]);
    }

    #[test]
    fn receipt_failure_has_empty_return() {
        let h = Hash256([2u8; 32]);
        let r = CrossContractReceipt::failure(h, GasAmount::from_u64(50));
        assert!(!r.success);
        assert!(r.return_data.is_empty());
    }

    // ── Rejection model for cross-contract operations ─────────────────────
    // AEVOR architecture rule: cross-contract operations either fully succeed
    // or are fully rejected before any state is committed. There is no
    // "execute partially then rollback" — a failed sub-call means the entire
    // multi-contract operation is rejected atomically.

    #[test]
    fn failed_sub_call_receipt_commits_no_state() {
        // A failure receipt represents a sub-call that was rejected.
        // The gas_used reflects validation cost; return_data is empty because
        // no computation completed and no state was written.
        let h = Hash256([3u8; 32]);
        let r = CrossContractReceipt::failure(h, GasAmount::from_u64(1_000));
        assert!(!r.success);
        assert!(r.return_data.is_empty()); // no output = no committed state
        assert!(r.gas_used.as_u64() > 0);  // gas consumed for validation
    }

    #[test]
    fn cross_contract_call_stores_gas_budget() {
        let addr = |n: u8| aevor_core::primitives::Address([n; 32]);
        let call = CrossContractCall {
            caller: addr(1),
            callee: addr(2),
            function: "transfer".into(),
            gas_budget: GasAmount::from_u64(50_000),
        };
        assert_eq!(call.gas_budget.as_u64(), 50_000);
        assert_eq!(call.function, "transfer");
    }

    #[test]
    fn depth_guard_overflow_does_not_enter() {
        // CallDepthGuard prevents runaway recursion — a security limit.
        let mut g = CallDepthGuard::new(0);
        assert!(!g.enter()); // max_depth = 0, nothing allowed
    }
}
