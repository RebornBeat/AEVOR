//! Execution context factory.
use aevor_core::execution::ExecutionContext;
use aevor_core::transaction::SignedTransaction;
use crate::ExecutionResult;

pub struct ContextFactory;
impl ContextFactory {
    pub fn from_transaction(_tx: &SignedTransaction) -> Option<ExecutionContext> { None }
}
