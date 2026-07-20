//! The real node engine.
//!
//! Unlike the lifecycle skeleton in [`crate::orchestrator`] (which flips state
//! flags), this instantiates and *runs* the actual subsystems and processes
//! transactions end-to-end:
//!
//! ```text
//! signed tx ──▶ signature verify (aevor-crypto agility)
//!           ──▶ DAG conflict rejection + VM execution + durable persist
//!               (aevor-execution ComposedExecutor over a LogBackend)
//!           ──▶ authenticated state commitment (aevor-storage MerkleProver)
//!           ──▶ finality proof over a validator committee (aevor-consensus)
//! ```
//!
//! Every stage is real: durable log-structured storage, real DAG conflict
//! detection, the real bytecode interpreter, a real binary Merkle tree, and a
//! real (populated) finality proof. No stubs on this path.

use aevor_consensus::engine::{AttestationCollection, ConsensusEngine};
use aevor_core::block::BlockAttestation;
use aevor_core::consensus::{ConsensusTimestamp, SecurityLevel};
use aevor_core::primitives::{
    Address, BlockHash, GasAmount, Hash256, ObjectId, Signature, ValidatorWeight,
};
use aevor_core::privacy::PrivacyLevel;
use aevor_core::storage::{MerkleProof, MerkleRoot, StorageKey, StorageValue};
use aevor_crypto::agility::verify_transaction;
use aevor_crypto::hash::Blake3Hasher;
use aevor_crypto::signatures::Ed25519KeyPair;
use aevor_dag::dependency::ReadWriteSet;
use aevor_execution::composed::ComposedExecutor;
use aevor_storage::backend::{BackendConfig, LogBackend};
use aevor_storage::merkle::MerkleProver;

use crate::{NodeError, NodeResult};

// The agility-aware transaction type is shared with clients via aevor-client
// (so any wallet scheme — Ed25519, ML-DSA, Hybrid — can submit). Re-exported
// here for the engine and its tests.
pub use aevor_client::exec::{NodeConnection, SubmitResponse};
pub use aevor_core::transaction::SignedTransaction;

/// Derive the DAG read/write set from a transaction body: reads from the
/// declared read set, writes from the declared write set, keyed by the
/// transaction hash. This is how the canonical rich transaction feeds the
/// engine's conflict-detection + execution pipeline.
fn read_write_set_of(tx: &aevor_core::transaction::Transaction) -> ReadWriteSet {
    ReadWriteSet {
        transaction: tx.hash,
        reads: tx.declared_read_set(),
        writes: tx.declared_write_set(),
    }
}

/// A member of the finalizing committee: a validator keypair and its weight.
pub struct CommitteeMember<'a> {
    /// The validator's signing key.
    pub keypair: &'a Ed25519KeyPair,
    /// The validator's voting weight.
    pub weight: u64,
}

/// Outcome of executing (not yet finalizing) a block.
#[derive(Clone, Debug)]
pub struct BlockOutcome {
    /// Block height.
    pub height: u64,
    /// Hash committing to this block (height ‖ state root ‖ accepted tx hashes).
    pub block_hash: BlockHash,
    /// Transactions accepted (valid signature, no conflict, executed OK).
    pub accepted: usize,
    /// Transactions rejected by execution (conflict or failed program).
    pub rejected: usize,
    /// Transactions dropped before execution for a bad/absent signature.
    pub bad_signature: usize,
    /// Authenticated state root after applying this block.
    pub state_root: MerkleRoot,
    /// Total gas consumed by executed programs.
    pub gas_used: u64,
}

/// Outcome of finalizing a block over a committee.
#[derive(Clone, Debug)]
pub struct FinalityOutcome {
    /// Whether the committee's weight met the required security level.
    pub finalized: bool,
    /// Number of validator signatures in the finality proof (0 if unfinalized).
    pub signature_count: usize,
    /// Signed voting weight recorded in the proof.
    pub signed_weight: u64,
}

/// The running node: real subsystems, composed.
pub struct NodeEngine {
    executor: ComposedExecutor,
    state: MerkleProver,
    consensus: ConsensusEngine,
    security_level: SecurityLevel,
    height: u64,
    gas_limit_per_tx: GasAmount,
    mempool: Vec<SignedTransaction>,
}

impl NodeEngine {
    /// Open a node over durable storage rooted at `data_dir`.
    ///
    /// # Errors
    /// Returns [`NodeError::InitializationFailed`] if the storage log cannot be
    /// opened.
    pub fn open(
        data_dir: std::path::PathBuf,
        owner: Address,
        privacy: PrivacyLevel,
        security_level: SecurityLevel,
    ) -> NodeResult<Self> {
        let mut path = data_dir;
        path.push("state.log");
        let backend = LogBackend::open(BackendConfig { path, ..BackendConfig::default() })
            .map_err(|e| NodeError::InitializationFailed {
                subsystem: "storage".to_string(),
                reason: e.to_string(),
            })?;
        let executor = ComposedExecutor::with_backend(Box::new(backend), owner, privacy);

        // Reconstruct the authenticated state tree from durable storage so the
        // state root survives a restart (not just the value store).
        let mut state = MerkleProver::new();
        let committed = executor
            .committed_objects()
            .map_err(|e| NodeError::InitializationFailed {
                subsystem: "state".to_string(),
                reason: e.to_string(),
            })?;
        for (id, data) in committed {
            state.insert(&Self::state_key(&id), StorageValue::from_bytes(data));
        }

        Ok(Self {
            executor,
            state,
            consensus: ConsensusEngine::new(security_level),
            security_level,
            height: 0,
            gas_limit_per_tx: GasAmount(1_000_000),
            mempool: Vec::new(),
        })
    }

    fn state_key(object: &ObjectId) -> StorageKey {
        StorageKey::from_bytes(object.0 .0.to_vec())
    }

    /// Submit a transaction to the mempool. The signature is verified up front;
    /// only well-signed transactions are admitted. Returns `true` if admitted.
    ///
    /// This is the entry point for both locally-originated transactions and
    /// transactions received from peers over a transport.
    #[must_use]
    pub fn submit(&mut self, tx: SignedTransaction) -> bool {
        if verify_transaction(&tx) {
            self.mempool.push(tx);
            true
        } else {
            false
        }
    }

    /// Number of transactions currently pending in the mempool.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.mempool.len()
    }

    /// Produce a block from all pending mempool transactions, executing them
    /// end-to-end and committing the results. The mempool is drained.
    ///
    /// # Errors
    /// Returns [`NodeError::SubsystemCrash`] if execution or a storage read
    /// fails.
    pub fn produce_block(&mut self) -> NodeResult<BlockOutcome> {
        let pending = std::mem::take(&mut self.mempool);
        self.process_block(pending)
    }

    /// Execute a block of signed transactions end-to-end and commit the results
    /// to the authenticated state. Does not finalize (see [`finalize_block`]).
    ///
    /// # Errors
    /// Returns [`NodeError::SubsystemCrash`] if execution or a storage read
    /// fails.
    ///
    /// [`finalize_block`]: NodeEngine::finalize_block
    pub fn process_block(&mut self, txs: Vec<SignedTransaction>) -> NodeResult<BlockOutcome> {
        // 1. Signature gate: only well-signed transactions proceed.
        let mut valid: Vec<(ReadWriteSet, Vec<u8>)> = Vec::new();
        let mut bad_signature = 0usize;
        for tx in txs {
            if verify_transaction(&tx) {
                let rw = read_write_set_of(&tx.transaction);
                valid.push((rw, tx.transaction.payload));
            } else {
                bad_signature += 1;
            }
        }

        // 2. Execute through the composed pipeline: DAG conflict rejection →
        //    VM execution → durable persistence.
        let outcome = self
            .executor
            .process_program_batch(&valid, self.gas_limit_per_tx)
            .map_err(|e| NodeError::SubsystemCrash {
                subsystem: "execution".to_string(),
                reason: e.to_string(),
            })?;

        // 3. Commit each written object into the authenticated state tree.
        let mut accepted_tx_hashes: Vec<Hash256> = Vec::new();
        for object_id in &outcome.written_object_ids {
            let record = self
                .executor
                .object(object_id)
                .map_err(|e| NodeError::SubsystemCrash {
                    subsystem: "storage".to_string(),
                    reason: e.to_string(),
                })?;
            if let Some(record) = record {
                self.state
                    .insert(&Self::state_key(object_id), StorageValue::from_bytes(record.data));
            }
        }
        for (rw, _) in &valid {
            accepted_tx_hashes.push(rw.transaction);
        }

        self.height += 1;
        let state_root = self.state.root();

        // 4. Compute the block hash committing to height, state root, and txs.
        let mut hasher = Blake3Hasher::new();
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&state_root.0 .0);
        for h in &accepted_tx_hashes {
            hasher.update(&h.0);
        }
        let block_hash: BlockHash = hasher.finalize().0;

        Ok(BlockOutcome {
            height: self.height,
            block_hash,
            accepted: outcome.accepted,
            rejected: outcome.rejected,
            bad_signature,
            state_root,
            gas_used: outcome.total_gas_used,
        })
    }

    /// Finalize a block by collecting attestations from a validator committee
    /// and producing a real finality proof.
    ///
    /// Each committee member signs the block hash; attestations are collected
    /// with their weights and, if the required security level is met, a
    /// populated finality proof is produced by the consensus engine.
    ///
    /// # Errors
    /// Infallible today, but returns `NodeResult` for future propagation.
    pub fn finalize_block(
        &mut self,
        block_hash: BlockHash,
        committee: &[CommitteeMember<'_>],
    ) -> NodeResult<FinalityOutcome> {
        let total_weight: u64 = committee.iter().map(|m| m.weight).sum();
        let mut collection =
            AttestationCollection::new(block_hash, self.security_level, ValidatorWeight(total_weight));

        for member in committee {
            let ed_sig = member.keypair.sign(&block_hash.0);
            let attestation = BlockAttestation {
                block_hash,
                validator_id: Hash256(member.keypair.public_key_bytes()),
                signature: Signature(ed_sig.0 .0),
                tee_attestation: None,
                timestamp: ConsensusTimestamp::GENESIS,
            };
            collection.add(attestation, ValidatorWeight(member.weight));
        }

        let result = self.consensus.finalize_round(&collection, 0);
        match result.finality_proof {
            Some(proof) => Ok(FinalityOutcome {
                finalized: true,
                signature_count: proof.signatures.len(),
                signed_weight: proof.total_weight.0,
            }),
            None => Ok(FinalityOutcome {
                finalized: false,
                signature_count: 0,
                signed_weight: 0,
            }),
        }
    }

    /// Current authenticated state root.
    #[must_use]
    pub fn state_root(&self) -> MerkleRoot {
        self.state.root()
    }

    /// Current block height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Produce a Merkle inclusion proof for an object's committed state.
    ///
    /// # Errors
    /// Infallible today; returns `NodeResult` for future propagation.
    pub fn prove_object(&self, object: &ObjectId) -> NodeResult<Option<MerkleProof>> {
        self.state
            .prove(&Self::state_key(object))
            .map_err(|e| NodeError::SubsystemCrash {
                subsystem: "storage".to_string(),
                reason: e.to_string(),
            })
    }

    /// Verify a Merkle inclusion proof against the current state root.
    #[must_use]
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        MerkleProver::verify(proof)
    }
}

/// An in-process [`NodeConnection`] over a live [`NodeEngine`].
///
/// This is the adapter a client uses to talk to a local node; a real transport
/// (HTTP/gRPC/QUIC) is a different `NodeConnection` implementation over the same
/// trait, so client code is identical whether the node is in-process or remote.
pub struct EngineConnection<'a> {
    engine: &'a mut NodeEngine,
}

impl<'a> EngineConnection<'a> {
    /// Wrap a mutable reference to an engine as a connection.
    pub fn new(engine: &'a mut NodeEngine) -> Self {
        Self { engine }
    }
}

impl NodeConnection for EngineConnection<'_> {
    fn submit_transaction(
        &mut self,
        tx: &SignedTransaction,
    ) -> aevor_client::ClientResult<SubmitResponse> {
        let admitted = self.engine.submit(tx.clone());
        Ok(SubmitResponse { admitted, tx_hash: tx.hash() })
    }

    fn query_object(
        &self,
        id: aevor_core::primitives::ObjectId,
    ) -> aevor_client::ClientResult<Option<aevor_core::storage::MerkleProof>> {
        match self.engine.prove_object(&id).map_err(|e| {
            aevor_client::ClientError::InvalidResponse { reason: e.to_string() }
        })? {
            Some(proof) if proof.is_inclusion => Ok(Some(proof)),
            _ => Ok(None),
        }
    }
}
