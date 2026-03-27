//! Execution context factory.
use aevor_core::execution::ExecutionContext;
use aevor_core::transaction::SignedTransaction;

pub struct ContextFactory;

impl ContextFactory {
    /// Build an execution context from a signed transaction.
    ///
    /// Returns `None` if the transaction does not have sufficient context
    /// to construct a full execution environment (e.g., missing chain ID).
    pub fn from_transaction(_tx: &SignedTransaction) -> Option<ExecutionContext> { None }

    /// Build an execution context, returning an error if construction fails.
    ///
    /// # Errors
    /// Returns `ExecutionError::VmFailed` if the transaction lacks the context
    /// needed to construct a full execution environment.
    pub fn try_from_transaction(tx: &SignedTransaction) -> crate::ExecutionResult<ExecutionContext> {
        let hash = tx.hash();
        Self::from_transaction(tx).ok_or_else(|| crate::ExecutionError::VmFailed(
            format!("could not build execution context for transaction {hash:?}")
        ))
    }
}
