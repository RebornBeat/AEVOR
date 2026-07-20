//! Transaction submission and querying against a node.
//!
//! The transaction type here is the single canonical
//! [`aevor_core::transaction::SignedTransaction`] — agility-aware (any wallet
//! scheme signs it via [`sign_transaction`]) and shared with the node engine.
//!
//! [`Client`] builds and signs transactions with a wallet and submits them over
//! a [`NodeConnection`], and it **verifies the Merkle proof** on every queried
//! object before trusting the data. `NodeConnection` is the seam a real
//! transport (HTTP/gRPC/QUIC) implements; an in-process implementation exercises
//! the full path in tests.

use aevor_core::crypto::MultiPublicKey;
use aevor_core::primitives::{Nonce, ObjectId, TransactionHash};
use aevor_core::storage::MerkleProof;
use aevor_core::transaction::{SignedTransaction, Transaction};
use aevor_crypto::agility::{sign_transaction, Signer};

use crate::verification::MerkleVerifier;
use crate::{ClientError, ClientResult};

/// Result of submitting a transaction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubmitResponse {
    /// Whether the node admitted the transaction (e.g. to its mempool).
    pub admitted: bool,
    /// The transaction hash.
    pub tx_hash: TransactionHash,
}

/// A connection to a node. A real transport (HTTP/gRPC/QUIC) implements this;
/// the node ships an in-process implementation over its engine.
pub trait NodeConnection {
    /// Submit a signed transaction to the node.
    ///
    /// # Errors
    /// Returns a client error if the underlying transport fails.
    fn submit_transaction(&mut self, tx: &SignedTransaction) -> ClientResult<SubmitResponse>;

    /// Query an object's committed state, returning a Merkle inclusion proof if
    /// present (the proof carries the value).
    ///
    /// # Errors
    /// Returns a client error if the underlying transport fails.
    fn query_object(&self, id: ObjectId) -> ClientResult<Option<MerkleProof>>;
}

/// A client that submits transactions and queries verified state from a node.
pub struct Client<C: NodeConnection, S: Signer> {
    wallet: S,
    connection: C,
    nonce: u64,
}

impl<C: NodeConnection, S: Signer> Client<C, S> {
    /// Create a client with a wallet and a node connection.
    pub fn new(wallet: S, connection: C) -> Self {
        Self { wallet, connection, nonce: 0 }
    }

    /// Build, sign, and submit a transaction that reads `reads`, writes
    /// `writes`, and carries `bytecode`. The client's nonce increments per call.
    ///
    /// # Errors
    /// Returns a client error if submission fails.
    pub fn submit(
        &mut self,
        reads: &[ObjectId],
        writes: &[ObjectId],
        bytecode: Vec<u8>,
    ) -> ClientResult<SubmitResponse> {
        let tx = Transaction::new_simple(
            self.wallet.public_key_multi(),
            Nonce(self.nonce),
            reads,
            writes,
            bytecode,
        );
        self.nonce += 1;
        let signed = sign_transaction(tx, &self.wallet);
        self.connection.submit_transaction(&signed)
    }

    /// Query an object and **verify its Merkle proof** before returning the
    /// data. Returns `None` if the object is not present.
    ///
    /// # Errors
    /// Returns [`ClientError::VerificationFailed`] if the returned proof does not
    /// verify, or a transport error.
    pub fn get_object(&self, id: ObjectId) -> ClientResult<Option<Vec<u8>>> {
        match self.connection.query_object(id)? {
            Some(proof) => {
                if !proof.is_inclusion || !MerkleVerifier::verify(&proof) {
                    return Err(ClientError::VerificationFailed {
                        reason: "object Merkle proof did not verify".to_string(),
                    });
                }
                Ok(Some(proof.value.0.clone()))
            }
            None => Ok(None),
        }
    }

    /// The wallet's public key (scheme-tagged).
    pub fn public_key(&self) -> MultiPublicKey {
        self.wallet.public_key_multi()
    }
}
