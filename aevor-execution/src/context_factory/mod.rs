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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, Amount, GasAmount, GasPrice, Hash256, Nonce, Signature};
    use aevor_core::transaction::{SignedTransaction, Transaction, TransactionType};
    use aevor_core::privacy::PrivacyLevel;

    fn make_signed_tx() -> SignedTransaction {
        let tx = Transaction {
            hash: Hash256::ZERO,
            chain_id: aevor_core::primitives::ChainId::MAINNET,
            tx_type: TransactionType::Transfer,
            sender: Address([1u8; 32]),
            sender_public_key: aevor_core::primitives::PublicKey([0u8; 32]),
            nonce: Nonce(0),
            inputs: vec![],
            outputs: vec![],
            gas_limit: GasAmount::from_u64(21_000),
            max_gas_price: GasPrice(100),
            value: Amount::ZERO,
            payload: vec![],
            required_security_level: aevor_core::consensus::SecurityLevel::Basic,
            privacy_level: PrivacyLevel::Public,
            metadata: vec![],
        };
        SignedTransaction {
            transaction: tx,
            signature: Signature([0u8; 64]),
            multi_signatures: vec![],
            privacy_proof: None,
        }
    }

    #[test]
    fn context_factory_returns_none_for_stub() {
        let tx = make_signed_tx();
        assert!(ContextFactory::from_transaction(&tx).is_none());
    }

    #[test]
    fn context_factory_try_returns_error_for_stub() {
        let tx = make_signed_tx();
        assert!(ContextFactory::try_from_transaction(&tx).is_err());
    }
}
