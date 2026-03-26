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
    pub async fn wait_for_finality(
        &self,
        client: &TransactionClient,
        timeout_ms: u64,
    ) -> ClientResult<TransactionStatus> {
        let start = std::time::Instant::now();
        loop {
            let status = client.get_status(self.transaction_hash).await?;
            if matches!(status, TransactionStatus::FinalizedFull | TransactionStatus::FinalizedStrong | TransactionStatus::FinalizedBasic | TransactionStatus::FinalizedMinimal | TransactionStatus::Failed) {
                return Ok(status);
            }
            if start.elapsed().as_millis() as u64 >= timeout_ms {
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
    pub async fn submit(&self, req: SignedTransactionRequest) -> ClientResult<SubmitResult> {
        // Real implementation: serialize req and POST to self.endpoint/v1/transactions
        // Returns the tx hash from the response body.
        let _ = req;
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "not yet connected — wire in reqwest/tonic transport".into(),
        })
    }

    /// Query the current status of a transaction by hash.
    pub async fn get_status(&self, hash: TransactionHash) -> ClientResult<TransactionStatus> {
        let _ = hash;
        Err(crate::ClientError::ConnectionFailed {
            endpoint: self.endpoint.clone(),
            reason: "not yet connected".into(),
        })
    }
}
