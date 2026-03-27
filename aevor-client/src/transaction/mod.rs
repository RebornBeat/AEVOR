//! Transaction submission: sign, submit, poll for finality.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::TransactionHash;
pub use aevor_core::transaction::TransactionStatus;
use aevor_core::transaction::SignedTransaction;
use crate::ClientResult;

/// A signed transaction ready for submission to the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedTransactionRequest {
    /// The fully-signed transaction.
    pub signed_tx: SignedTransaction,
}

impl SignedTransactionRequest {
    /// Wrap a signed transaction for submission.
    pub fn new(signed_tx: SignedTransaction) -> Self { Self { signed_tx } }
}

/// Result returned after successfully submitting a transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitResult {
    /// Hash of the accepted transaction (used for polling status).
    pub transaction_hash: TransactionHash,
    /// Initial status at the time of submission (usually `Pending`).
    pub status: TransactionStatus,
}

/// Polls a transaction hash until finality or timeout.
pub struct TransactionPoller {
    /// Hash of the transaction to poll.
    pub transaction_hash: TransactionHash,
    /// Polling interval in milliseconds.
    pub interval_ms: u64,
}

impl TransactionPoller {
    /// Create a poller for the given transaction hash.
    ///
    /// `interval_ms` controls how often to query the node (default 500ms).
    pub fn new(transaction_hash: TransactionHash, interval_ms: u64) -> Self {
        Self { transaction_hash, interval_ms }
    }

    /// Wait until the transaction is finalized or the timeout expires.
    ///
    /// Returns the final `TransactionStatus`. Returns `Pending` on timeout.
    ///
    /// # Errors
    /// Returns an error if the underlying status query fails (connection error).
    pub async fn wait_for_finality(
        &self,
        client: &TransactionClient,
        timeout_ms: u64,
    ) -> ClientResult<TransactionStatus> {
        let start = std::time::Instant::now();
        loop {
            let status = client.get_status(self.transaction_hash)?;
            if matches!(status, TransactionStatus::FinalizedFull | TransactionStatus::FinalizedStrong | TransactionStatus::FinalizedBasic | TransactionStatus::FinalizedMinimal | TransactionStatus::Failed) {
                return Ok(status);
            }
            #[allow(clippy::cast_possible_truncation)] // timeout_ms comparison: milliseconds always fit in u64
            if u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX) >= timeout_ms {
                return Ok(TransactionStatus::Pending);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(self.interval_ms)).await;
        }
    }
}

/// Client for submitting transactions and querying their status.
pub struct TransactionClient {
    endpoint: String,
}

impl TransactionClient {
    /// Create a transaction client pointing at the given endpoint.
    pub fn new(endpoint: String) -> Self { Self { endpoint } }

    /// The endpoint this client connects to.
    pub fn endpoint(&self) -> &str { &self.endpoint }

    /// Submit a signed transaction to the network.
    ///
    /// Returns a `SubmitResult` with the transaction hash and initial status.
    /// The transaction is not yet finalized — use `TransactionPoller` to wait.
    ///
    /// # Errors
    /// Returns an error if the transport is not yet connected or the request fails.
    pub fn submit(&self, req: &SignedTransactionRequest) -> ClientResult<SubmitResult> {
        // Real implementation: serialize req and POST to self.endpoint/v1/transactions
        // Returns the tx hash from the response body.
        let _ = req;
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "not yet connected — wire in reqwest/tonic transport".into(),
        })
    }

    /// Query the current status of a transaction by hash.
    ///
    /// # Errors
    /// Returns an error if the transport is not yet connected or the request fails.
    pub fn get_status(&self, hash: TransactionHash) -> ClientResult<TransactionStatus> {
        let _ = hash;
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "not yet connected".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{
        Address, Amount, ChainId, GasAmount, GasPrice, Hash256, Nonce, ObjectId, PublicKey,
        Signature, TransactionHash,
    };
    use aevor_core::transaction::{
        SignedTransaction, Transaction, TransactionInput, TransactionOutput, TransactionType,
        InputAccessType,
    };
    use aevor_core::privacy::PrivacyLevel;
    use aevor_core::consensus::SecurityLevel;

    fn tx_hash(n: u8) -> TransactionHash { Hash256([n; 32]) }
    fn addr(n: u8) -> Address { Address([n; 32]) }
    fn obj_id(n: u8) -> ObjectId { ObjectId(Hash256([n; 32])) }

    /// Build a minimal but fully-specified `SignedTransaction` for testing.
    ///
    /// All optional collections are empty; nonce is 0; gas limit is 21,000;
    /// signature is a zero-filled 64-byte array. This exercises the entire
    /// struct surface without needing a live key or network.
    fn minimal_signed_tx() -> SignedTransaction {
        let transaction = Transaction {
            hash: tx_hash(0xAB),
            chain_id: ChainId::MAINNET,
            tx_type: TransactionType::Transfer,
            sender: addr(1),
            sender_public_key: PublicKey([0u8; 32]),
            nonce: Nonce(0),
            inputs: vec![TransactionInput {
                object_id: obj_id(1),
                expected_version: 0,
                content_hash: Hash256::ZERO,
                access_type: InputAccessType::ReadWrite,
            }],
            outputs: vec![TransactionOutput {
                object_id: obj_id(2),
                data: vec![],
                privacy_level: PrivacyLevel::Public,
                owner: addr(2),
                is_new: true,
            }],
            gas_limit: GasAmount::from_u64(21_000),
            max_gas_price: GasPrice(1_000),
            value: Amount::ZERO,
            payload: vec![],
            required_security_level: SecurityLevel::Basic,
            privacy_level: PrivacyLevel::Public,
            metadata: vec![],
        };
        SignedTransaction {
            transaction,
            signature: Signature([0u8; 64]),
            multi_signatures: vec![],
            privacy_proof: None,
        }
    }

    #[test]
    fn signed_transaction_request_wraps_tx() {
        let tx = minimal_signed_tx();
        let expected_hash = tx.transaction.hash;
        let req = SignedTransactionRequest::new(tx);
        assert_eq!(req.signed_tx.transaction.hash, expected_hash);
    }

    #[test]
    fn submit_returns_error_when_disconnected() {
        let client = TransactionClient::new("http://localhost:8731".into());
        let req = SignedTransactionRequest::new(minimal_signed_tx());
        assert!(client.submit(&req).is_err());
    }

    #[test]
    fn submit_result_stores_hash_and_status() {
        let r = SubmitResult {
            transaction_hash: tx_hash(1),
            status: TransactionStatus::Pending,
        };
        assert_eq!(r.transaction_hash, tx_hash(1));
        assert!(matches!(r.status, TransactionStatus::Pending));
    }

    #[test]
    fn transaction_poller_stores_hash_and_interval() {
        let poller = TransactionPoller::new(tx_hash(5), 500);
        assert_eq!(poller.transaction_hash, tx_hash(5));
        assert_eq!(poller.interval_ms, 500);
    }

    #[test]
    fn transaction_client_endpoint() {
        let client = TransactionClient::new("http://localhost:8731".into());
        assert_eq!(client.endpoint(), "http://localhost:8731");
    }

    #[test]
    fn transaction_client_get_status_returns_error_when_disconnected() {
        let client = TransactionClient::new("http://localhost:8731".into());
        assert!(client.get_status(tx_hash(1)).is_err());
    }

    #[test]
    fn minimal_signed_tx_is_transfer_type() {
        let tx = minimal_signed_tx();
        assert!(matches!(tx.transaction.tx_type, TransactionType::Transfer));
        assert_eq!(tx.transaction.sender, addr(1));
        assert_eq!(tx.transaction.gas_limit, GasAmount::from_u64(21_000));
        assert!(tx.multi_signatures.is_empty());
        assert!(tx.privacy_proof.is_none());
    }

    #[test]
    fn minimal_signed_tx_inputs_and_outputs() {
        let tx = minimal_signed_tx();
        assert_eq!(tx.transaction.inputs.len(), 1);
        assert_eq!(tx.transaction.outputs.len(), 1);
        assert_eq!(tx.transaction.inputs[0].object_id, obj_id(1));
        assert_eq!(tx.transaction.outputs[0].owner, addr(2));
    }
}
