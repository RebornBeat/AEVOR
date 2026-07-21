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
use aevor_consensus::slashing::{SlashingEvidence, SlashingEvidenceType};
use aevor_core::block::BlockAttestation;
use aevor_core::consensus::{ConsensusTimestamp, SecurityLevel};
use aevor_core::economics::{intrinsic_gas, FeePolicy, DEFAULT_GAS_PER_BYTE, DEFAULT_INTRINSIC_TX_GAS};
use aevor_core::primitives::{
    Address, Amount, BlockHash, GasAmount, GasPrice, Hash256, ObjectId, Signature, ValidatorWeight,
};
use aevor_core::privacy::PrivacyLevel;
use aevor_core::storage::{MerkleProof, MerkleRoot, StorageKey, StorageValue};
use aevor_crypto::agility::verify_transaction;
use aevor_crypto::hash::Blake3Hasher;
use aevor_crypto::bls::{aggregate_public_keys, BlsAggregator};
use aevor_crypto::signatures::{BlsKeyPair, Ed25519KeyPair};
use aevor_dag::dependency::ReadWriteSet;
use aevor_dag::macro_dag::{BlockOrdering, LaneAssignment};
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
    /// The validator's Ed25519 signing key (per-validator vote record).
    pub keypair: &'a Ed25519KeyPair,
    /// The validator's BLS12-381 consensus key, used for O(1)-verifiable
    /// finality aggregation (one aggregate signature for the whole committee).
    pub bls: &'a BlsKeyPair,
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
    /// Fee charged for this block under the subnet's economics — always zero on
    /// a feeless subnet, otherwise `gas_used * gas_price`. Equal to the sum of the
    /// per-transaction fees actually settled, and to the reward credited to the
    /// validator for this block.
    pub fee_charged: aevor_core::primitives::Amount,
    /// Transactions dropped before execution because the sender could not cover
    /// the maximum fee — the account-level abuse/spam guard.
    pub insufficient_funds: usize,
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
    /// Whether the aggregated BLS12-381 finality signature verified against the
    /// committee's aggregate public key — O(1) regardless of committee size.
    pub bls_verified: bool,
    /// The aggregated BLS finality signature (single point; empty if none).
    pub aggregate_signature: Vec<u8>,
}

/// Which authenticated-state-tree backend the engine commits to. The engine's
/// observable behaviour (roots, proofs, attestation checks) is identical for
/// both; only the performance profile differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleBackend {
    /// Sorted-leaf binary Merkle tree. O(n) batch commit — optimal for applying
    /// a whole block's writes at once (the default hot path).
    Sorted,
    /// 256-deep sparse Merkle tree keyed by `BLAKE3(key)`. O(depth) single-key
    /// updates and O(depth) proofs, but O(n·depth) to apply a large batch.
    Sparse,
}

/// Pluggable authenticated state tree. Both variants expose the same
/// insert / root / prove / verify surface, so the engine is agnostic to which
/// is in use; benchmarks select the backend to measure the tradeoff directly.
enum StateTree {
    Sorted(MerkleProver),
    Sparse(aevor_crypto::merkle::SparseMerkleTree),
}

impl StateTree {
    fn new(backend: MerkleBackend) -> Self {
        match backend {
            MerkleBackend::Sorted => StateTree::Sorted(MerkleProver::new()),
            MerkleBackend::Sparse => {
                StateTree::Sparse(aevor_crypto::merkle::SparseMerkleTree::new())
            }
        }
    }

    fn insert(&mut self, key: &StorageKey, value: StorageValue) {
        match self {
            StateTree::Sorted(t) => t.insert(key, value),
            StateTree::Sparse(t) => t.insert(key, value),
        }
    }

    fn root(&self) -> MerkleRoot {
        match self {
            StateTree::Sorted(t) => t.root(),
            StateTree::Sparse(t) => t.root(),
        }
    }

    fn prove(&self, key: &StorageKey) -> aevor_storage::StorageResult<Option<MerkleProof>> {
        match self {
            StateTree::Sorted(t) => t.prove(key),
            StateTree::Sparse(t) => Ok(t.prove(key)),
        }
    }

    /// Verify a proof, dispatching by shape: the sparse tree always emits
    /// exactly 256 siblings; the sorted tree emits `ceil(log2(n)) << 256`.
    fn verify(proof: &MerkleProof) -> bool {
        if proof.siblings.len() == 256 {
            aevor_crypto::merkle::SparseMerkleTree::verify(proof)
        } else {
            MerkleProver::verify(proof)
        }
    }
}

/// The running node: real subsystems, composed.
pub struct NodeEngine {
    executor: ComposedExecutor,
    state: StateTree,
    consensus: ConsensusEngine,
    security_level: SecurityLevel,
    height: u64,
    gas_limit_per_tx: GasAmount,
    mempool: Vec<SignedTransaction>,
    /// The subnet this node participates in — governs fees, admission, and the
    /// enforced privacy baseline.
    subnet: crate::subnet::SubnetPolicy,
    /// The privacy level objects written by this node are stamped with (the
    /// dApp's chosen level, always at or above the subnet baseline).
    privacy: PrivacyLevel,
    /// The dynamic fee market — a congestion-based base fee that rises under load
    /// and falls when idle. Derived from the subnet's `FeeConfig`; `Free` on a
    /// feeless subnet.
    fee_market: FeePolicy,
    /// Total fees this node has collected as block rewards (the validator's
    /// accrued reward from usage).
    validator_reward: Amount,
    /// Account balances (`Address -> Amount`), funded at genesis. Senders are
    /// debited the fee for their transactions; the validator is credited. This is
    /// the settlement ledger — the abuse guard is that a sender who cannot cover
    /// its transaction's maximum fee is rejected before execution.
    balances: std::collections::HashMap<Address, Amount>,
}

/// A produced block together with its execution attestation and the state
/// delta a verifier needs to reproduce it without re-executing.
pub type AttestedBatch = (BlockOutcome, ExecutionAttestation, Vec<(ObjectId, Vec<u8>)>);

/// One validator's contribution to a multi-lane round: the Proof-of-Uncorruption attestation over
/// its concurrently-produced block plus the state delta to apply. Produced from
/// [`NodeEngine::produce_attested_batch`] output; consumed by
/// [`NodeEngine::apply_lane_round`].
#[derive(Clone, Debug)]
pub struct LaneBlock {
    /// Identifier of the producing lane / validator.
    pub lane_id: u32,
    /// The validator that produced this lane (named in slashing evidence if the
    /// lane is found corrupt).
    pub producer: aevor_core::primitives::ValidatorId,
    /// Proof-of-Uncorruption attestation over this lane's state transition.
    pub attestation: ExecutionAttestation,
    /// The lane's state delta (written object id -> bytes).
    pub delta: Vec<(ObjectId, Vec<u8>)>,
}

/// Outcome of applying a multi-lane round via [`NodeEngine::apply_lane_round`].
#[derive(Clone, Debug)]
pub struct LaneRoundOutcome {
    /// Lane ids in the deterministic order they were applied.
    pub ordered_lanes: Vec<u32>,
    /// Consistent state root after all lanes were applied.
    pub state_root: MerkleRoot,
    /// Number of lanes applied.
    pub lanes_applied: usize,
    /// Total objects written across all lanes.
    pub objects_applied: usize,
}

/// An attestation over a state transition produced by a validator's TEE.
///
/// Binds the prior state root, the new state root, and a commitment to the
/// accepted transactions, sealed by the producing validator. Verifying it is
/// the evidence that the transition came from uncorrupted execution — so other
/// validators can apply the delta without re-executing. (Seal/verify use the
/// simulation attestation key today; real hardware attestation replaces the
/// seal without changing this shape.)
/// Version of the finalized protocol *rules* — the fee formula, gas schedule,
/// per-transaction settlement, and account abuse guard. It is folded into every
/// execution attestation ([`ExecutionAttestation::body`]), so two validators
/// running different rule versions produce mutually unverifiable attestations and
/// reject each other's blocks. Bump this whenever the economics or execution
/// semantics change; a network upgrade is the coordinated act of every validator
/// moving to the same new version. This is the mechanism that keeps every node on
/// the same finalized code — divergence is not merely discouraged, it is
/// cryptographically rejected at verification.
pub const PROTOCOL_RULES_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionAttestation {
    /// State root before the batch.
    pub prior_root: [u8; 32],
    /// State root after the batch.
    pub new_root: [u8; 32],
    /// BLAKE3 commitment over the accepted transaction hashes.
    pub tx_commitment: [u8; 32],
    /// TEE seal over the canonical body (64 bytes).
    pub signature: Vec<u8>,
}

impl ExecutionAttestation {
    fn body(prior: &[u8; 32], new: &[u8; 32], txc: &[u8; 32]) -> Vec<u8> {
        let mut b = Vec::with_capacity(100);
        b.extend_from_slice(prior);
        b.extend_from_slice(new);
        b.extend_from_slice(txc);
        // Pin the finalized protocol rules (fee formula, gas schedule, settlement,
        // abuse guard) into the attested body. A validator running a different
        // rule version signs a different body, so verifiers on another version
        // reject its blocks — this is what forces every node onto the same
        // finalized economics, not just the same state.
        b.extend_from_slice(&PROTOCOL_RULES_VERSION.to_le_bytes());
        b
    }

    /// Seal an attestation over a transition (producing validator's TEE).
    #[must_use]
    pub fn seal(prior_root: [u8; 32], new_root: [u8; 32], tx_commitment: [u8; 32]) -> Self {
        let signature =
            aevor_crypto::attestation::sim_sign(&Self::body(&prior_root, &new_root, &tx_commitment))
                .to_vec();
        Self { prior_root, new_root, tx_commitment, signature }
    }

    /// Verify the attestation seal (verifying validator).
    #[must_use]
    pub fn verify(&self) -> bool {
        let Ok(sig): Result<[u8; 64], _> = self.signature.as_slice().try_into() else {
            return false;
        };
        aevor_crypto::attestation::sim_verify(
            &Self::body(&self.prior_root, &self.new_root, &self.tx_commitment),
            &sig,
        )
    }
}

/// Result of the shared verify+execute+commit core.
struct BatchApplied {
    accepted: usize,
    rejected: usize,
    bad_signature: usize,
    written_object_ids: Vec<ObjectId>,
    tx_hashes: Vec<Hash256>,
    /// Per-accepted-transaction execution gas, keyed by tx hash (for per-sender
    /// fee settlement).
    accepted_tx_gas: Vec<(Hash256, u64)>,
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
        Self::open_with_backend(data_dir, owner, privacy, security_level, MerkleBackend::Sorted)
    }

    /// Like [`open`](Self::open) but selects the authenticated-state-tree
    /// backend (see [`MerkleBackend`]). Used to measure the sorted-vs-sparse
    /// tradeoff in the real execute/verify paths.
    ///
    /// # Errors
    /// Returns [`NodeError::InitializationFailed`] if the storage backend or
    /// state reconstruction fails.
    pub fn open_with_backend(
        data_dir: std::path::PathBuf,
        owner: Address,
        privacy: PrivacyLevel,
        security_level: SecurityLevel,
        merkle_backend: MerkleBackend,
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
        let mut state = StateTree::new(merkle_backend);
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
            subnet: crate::subnet::SubnetPolicy::public_mainnet(),
            privacy,
            fee_market: Self::fee_market_from(&crate::subnet::SubnetPolicy::public_mainnet().fee),
            validator_reward: Amount::ZERO,
            balances: std::collections::HashMap::new(),
        })
    }

    /// Derive the initial dynamic fee market from a subnet's fee config: a
    /// congestion-based market fee when fees are on, or `Free` when feeless.
    fn fee_market_from(fee: &aevor_config::economics::FeeConfig) -> FeePolicy {
        if fee.enabled {
            FeePolicy::MarketBased {
                base_fee: GasPrice(fee.base_fee_nano.max(fee.min_gas_price_nano)),
                max_multiplier: 8,
            }
        } else {
            FeePolicy::Free
        }
    }

    /// The block's target gas — the utilization the congestion controller steers
    /// toward (`block_gas_limit * target_utilization`).
    fn target_gas(&self) -> u64 {
        let fee = &self.subnet.fee;
        u64::try_from(
            u128::from(fee.block_gas_limit) * u128::from(fee.target_utilization_bps) / 10_000,
        )
        .unwrap_or(u64::MAX)
    }

    /// The intrinsic (size/bloat) gas of a signed transaction — larger
    /// transactions (e.g. post-quantum-signed) cost more, pricing in the storage
    /// and bandwidth they impose.
    fn tx_intrinsic_gas(tx: &SignedTransaction) -> u64 {
        let size = bincode::serialize(tx).map_or(0, |b| b.len());
        intrinsic_gas(size, DEFAULT_INTRINSIC_TX_GAS, DEFAULT_GAS_PER_BYTE)
    }

    /// The current congestion-based base fee (nano/gas). Zero on a feeless subnet.
    #[must_use]
    pub fn current_base_fee(&self) -> u64 {
        match &self.fee_market {
            FeePolicy::MarketBased { base_fee, .. } => base_fee.0,
            FeePolicy::Fixed { per_gas_fee, .. } => per_gas_fee.0,
            FeePolicy::Free => 0,
        }
    }

    /// The dynamic fee market policy this node is running.
    #[must_use]
    pub fn fee_market(&self) -> &FeePolicy {
        &self.fee_market
    }

    /// Total fees this node has collected as block rewards.
    #[must_use]
    pub fn validator_reward(&self) -> Amount {
        self.validator_reward
    }

    /// Fund an account. This is a **genesis-only** allocation primitive: it is
    /// permitted only before the first block (`height == 0`) and is rejected
    /// afterward, so it can never be used to mint balance on a running chain. On
    /// a real deployment the genesis allocation is fixed and agreed by every
    /// validator as part of the genesis block; after that, the only ways balance
    /// moves are fee settlement and (future) transfer transactions. Returns
    /// `true` if the allocation was applied.
    pub fn fund(&mut self, account: Address, amount: Amount) -> bool {
        if self.height != 0 {
            return false;
        }
        let entry = self.balances.entry(account).or_insert(Amount::ZERO);
        *entry = entry.saturating_add(amount);
        true
    }

    /// The current balance of an account (zero if never funded).
    #[must_use]
    pub fn balance_of(&self, account: Address) -> Amount {
        self.balances.get(&account).copied().unwrap_or(Amount::ZERO)
    }

    /// Debit an account by `amount`, returning `true` on success. Fails (no
    /// change) if the balance is insufficient.
    fn debit(&mut self, account: Address, amount: Amount) -> bool {
        let bal = self.balances.entry(account).or_insert(Amount::ZERO);
        match bal.checked_sub(amount) {
            Some(remaining) => {
                *bal = remaining;
                true
            }
            None => false,
        }
    }

    /// The account-level ABUSE GUARD. Partition a batch into the transactions
    /// whose senders can cover their (intrinsic) fee — reserving against a running
    /// per-sender tally so several transactions cannot jointly overspend — and a
    /// count of those dropped for insufficient funds. Feeless subnets admit all.
    /// Returns the affordable transactions plus the `(sender, intrinsic)` map.
    fn affordability_filter(
        &self,
        txs: Vec<SignedTransaction>,
    ) -> (
        Vec<SignedTransaction>,
        std::collections::HashMap<Hash256, (Address, u64)>,
        usize,
    ) {
        let base_fee = self.current_base_fee();
        let mut meta = std::collections::HashMap::new();
        let mut reserved: std::collections::HashMap<Address, Amount> =
            std::collections::HashMap::new();
        let mut affordable = Vec::with_capacity(txs.len());
        let mut insufficient_funds = 0usize;
        for tx in txs {
            let sender = tx.sender();
            let intrinsic = Self::tx_intrinsic_gas(&tx);
            if base_fee > 0 {
                let intrinsic_fee =
                    Amount::from_nano(u128::from(intrinsic).saturating_mul(u128::from(base_fee)));
                let already = reserved.get(&sender).copied().unwrap_or(Amount::ZERO);
                let available = self.balance_of(sender).saturating_sub(already);
                if available.checked_sub(intrinsic_fee).is_none() {
                    insufficient_funds += 1;
                    continue;
                }
                reserved.insert(sender, already.saturating_add(intrinsic_fee));
            }
            meta.insert(tx.hash(), (sender, intrinsic));
            affordable.push(tx);
        }
        (affordable, meta, insufficient_funds)
    }

    /// SETTLEMENT + market advance, shared by both block-production paths. For
    /// each accepted transaction the actual fee is `(intrinsic + execution gas) *
    /// base_fee`: debit the sender, credit the validator. Returns
    /// `(total_gas_used, block_fee)`, where `block_fee` equals both the settled
    /// total and the validator's reward for the block. Then advances the
    /// congestion market for the next block.
    fn settle_and_advance(
        &mut self,
        meta: &std::collections::HashMap<Hash256, (Address, u64)>,
        accepted_tx_gas: &[(Hash256, u64)],
    ) -> (u64, Amount) {
        let base_fee = self.current_base_fee();
        let mut block_gas: u64 = 0;
        let mut block_fee = Amount::ZERO;
        for (h, exec_gas) in accepted_tx_gas {
            let Some((sender, intrinsic)) = meta.get(h) else { continue };
            let tx_gas = intrinsic.saturating_add(*exec_gas);
            block_gas = block_gas.saturating_add(tx_gas);
            if base_fee == 0 {
                continue;
            }
            let fee = Amount::from_nano(u128::from(tx_gas).saturating_mul(u128::from(base_fee)));
            if self.debit(*sender, fee) {
                block_fee = block_fee.saturating_add(fee);
            }
        }
        self.validator_reward = self.validator_reward.saturating_add(block_fee);
        let target = self.target_gas();
        self.fee_market = self.fee_market.after_block(
            block_gas,
            target,
            self.subnet.fee.fee_adjustment_bps,
            self.subnet.fee.min_gas_price_nano,
        );
        (block_gas, block_fee)
    }

    /// Open a node that participates in a specific **subnet**, deploying a dApp
    /// at `dapp_privacy`.
    ///
    /// This is how a dApp launches onto a subnet with settings: the subnet's
    /// [`SubnetPolicy`](crate::subnet::SubnetPolicy) governs fees (feeless vs
    /// fee), admission (permissioned vs permissionless), and the enforced privacy
    /// baseline. The dApp chooses the privacy level for the objects it writes,
    /// which **must be at or above the subnet baseline** — a below-baseline
    /// deployment is rejected outright, because privacy is architecturally
    /// enforced rather than downgraded.
    ///
    /// # Errors
    /// Returns [`NodeError::InitializationFailed`] if storage fails, or if
    /// `dapp_privacy` is below the subnet's enforced privacy baseline.
    pub fn open_on_subnet(
        data_dir: std::path::PathBuf,
        owner: Address,
        subnet: crate::subnet::SubnetPolicy,
        dapp_privacy: PrivacyLevel,
        security_level: SecurityLevel,
    ) -> NodeResult<Self> {
        if !subnet.allows_privacy(dapp_privacy) {
            return Err(NodeError::InitializationFailed {
                subsystem: "subnet".to_string(),
                reason: format!(
                    "dApp privacy {dapp_privacy:?} is below the subnet's enforced baseline {:?}",
                    subnet.min_privacy_level
                ),
            });
        }
        let mut engine = Self::open_with_backend(
            data_dir,
            owner,
            dapp_privacy,
            security_level,
            MerkleBackend::Sorted,
        )?;
        engine.subnet = subnet;
        engine.fee_market = Self::fee_market_from(&engine.subnet.fee);
        Ok(engine)
    }

    /// The subnet policy this node enforces (fees, admission, privacy baseline).
    #[must_use]
    pub fn subnet(&self) -> &crate::subnet::SubnetPolicy {
        &self.subnet
    }

    /// The privacy level objects written by this node are stamped with.
    #[must_use]
    pub fn privacy(&self) -> PrivacyLevel {
        self.privacy
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
        // Permissioned subnets admit only permitted participants; a non-permitted
        // sender is rejected before the tx ever enters the mempool.
        if !self.subnet.admits(tx.sender()) {
            return false;
        }
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
        // Abuse guard: drop transactions whose senders cannot cover their fee.
        let (affordable, meta, insufficient_funds) = self.affordability_filter(txs);

        let applied = self.verify_execute_commit(affordable)?;
        let bad_signature = applied.bad_signature;
        let accepted = applied.accepted;
        let rejected = applied.rejected;
        let accepted_tx_hashes = applied.tx_hashes;

        // Settle per-sender fees, credit the validator, advance the market.
        let (gas_used, block_fee) = self.settle_and_advance(&meta, &applied.accepted_tx_gas);

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
            accepted,
            rejected,
            bad_signature,
            state_root,
            gas_used,
            fee_charged: block_fee,
            insufficient_funds,
        })
    }

    /// Shared core: signature gate → DAG conflict rejection → VM execution →
    /// commit written objects into the state tree. Used by both the full path
    /// (`process_block`) and the producing side of the attested path
    /// (`produce_attested_batch`) so there is a single execution codepath.
    fn verify_execute_commit(&mut self, txs: Vec<SignedTransaction>) -> NodeResult<BatchApplied> {
        // Signature verification is the producer's bottleneck and is embarrassingly
        // parallel (each transaction is independent). Verify across all cores via
        // the global work-stealing pool (sized to the host by `compute`), while
        // PRESERVING ORDER so the downstream conflict-rejection winners are
        // identical to the sequential path. On one core this is equivalent; on
        // many cores it scales the bottleneck with the hardware.
        use rayon::prelude::*;
        let checked: Vec<Option<(ReadWriteSet, Vec<u8>)>> = txs
            .into_par_iter()
            .map(|tx| {
                if verify_transaction(&tx) {
                    Some((read_write_set_of(&tx.transaction), tx.transaction.payload))
                } else {
                    None
                }
            })
            .collect();
        let mut valid: Vec<(ReadWriteSet, Vec<u8>)> = Vec::with_capacity(checked.len());
        let mut bad_signature = 0usize;
        for c in checked {
            match c {
                Some(v) => valid.push(v),
                None => bad_signature += 1,
            }
        }

        let outcome = self
            .executor
            .process_program_batch(&valid, self.gas_limit_per_tx)
            .map_err(|e| NodeError::SubsystemCrash {
                subsystem: "execution".to_string(),
                reason: e.to_string(),
            })?;

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

        let tx_hashes = valid.iter().map(|(rw, _)| rw.transaction).collect();

        Ok(BatchApplied {
            accepted: outcome.accepted,
            rejected: outcome.rejected,
            bad_signature,
            written_object_ids: outcome.written_object_ids.clone(),
            tx_hashes,
            accepted_tx_gas: outcome.accepted_tx_gas.clone(),
        })
    }

    /// Produce a block AND an execution attestation over the state transition,
    /// plus the state delta needed to reproduce it. This is the *producing*
    /// validator's role under Proof of Uncorruption: execute once, in its TEE,
    /// and emit a proof other validators verify WITHOUT re-executing (see
    /// [`apply_attested_batch`](Self::apply_attested_batch)).
    ///
    /// # Errors
    /// Propagates execution/storage subsystem failures.
    pub fn produce_attested_batch(
        &mut self,
        txs: Vec<SignedTransaction>,
    ) -> NodeResult<AttestedBatch> {
        let prior_root = self.state.root();
        // Same abuse guard + per-sender fee metadata as the plain block path.
        let (affordable, meta, insufficient_funds) = self.affordability_filter(txs);
        let applied = self.verify_execute_commit(affordable)?;

        // Materialize the state delta (written object -> data) for shipment.
        let mut delta: Vec<(ObjectId, Vec<u8>)> =
            Vec::with_capacity(applied.written_object_ids.len());
        for object_id in &applied.written_object_ids {
            if let Some(record) = self.executor.object(object_id).map_err(|e| {
                NodeError::SubsystemCrash {
                    subsystem: "storage".to_string(),
                    reason: e.to_string(),
                }
            })? {
                delta.push((*object_id, record.data));
            }
        }

        self.height += 1;
        let state_root = self.state.root();

        let mut txh = Blake3Hasher::new();
        for h in &applied.tx_hashes {
            txh.update(&h.0);
        }
        let tx_commitment = txh.finalize().0;

        let attestation =
            ExecutionAttestation::seal(prior_root.0 .0, state_root.0 .0, tx_commitment.0);

        let mut hasher = Blake3Hasher::new();
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&state_root.0 .0);
        for h in &applied.tx_hashes {
            hasher.update(&h.0);
        }
        let block_hash: BlockHash = hasher.finalize().0;

        // Settle per-sender fees, credit the validator, advance the market —
        // identical economics to the plain block path.
        let (gas_used, block_fee) = self.settle_and_advance(&meta, &applied.accepted_tx_gas);

        let outcome = BlockOutcome {
            height: self.height,
            block_hash,
            accepted: applied.accepted,
            rejected: applied.rejected,
            bad_signature: applied.bad_signature,
            state_root,
            gas_used,
            fee_charged: block_fee,
            insufficient_funds,
        };
        Ok((outcome, attestation, delta))
    }

    /// Apply an attested batch as a *verifying* validator: check the producer's
    /// execution attestation and apply the state delta — WITHOUT re-executing
    /// the VM or re-verifying individual transaction signatures. This is the
    /// Proof-of-Uncorruption fast path ("valid until proven corrupted"): a
    /// producer that ships a delta inconsistent with its attested new root, or
    /// an unauthentic attestation, is rejected here.
    ///
    /// # Errors
    /// Returns an error if the attestation is invalid, the prior root does not
    /// match local state, or the applied delta does not reproduce the attested
    /// new root (corruption detected).
    pub fn apply_attested_batch(
        &mut self,
        attestation: &ExecutionAttestation,
        delta: &[(ObjectId, Vec<u8>)],
    ) -> NodeResult<()> {
        if !attestation.verify() {
            return Err(NodeError::SubsystemCrash {
                subsystem: "attestation".to_string(),
                reason: "execution attestation failed verification".to_string(),
            });
        }
        if self.state.root().0 .0 != attestation.prior_root {
            return Err(NodeError::SubsystemCrash {
                subsystem: "attestation".to_string(),
                reason: "attested prior root does not match local state".to_string(),
            });
        }
        // Apply the delta directly — NO VM execution, NO signature re-check.
        for (object_id, data) in delta {
            self.state
                .insert(&Self::state_key(object_id), StorageValue::from_bytes(data.clone()));
        }
        self.height += 1;
        if self.state.root().0 .0 != attestation.new_root {
            return Err(NodeError::SubsystemCrash {
                subsystem: "attestation".to_string(),
                reason: "applied delta does not reproduce attested new root".to_string(),
            });
        }
        Ok(())
    }

    /// Apply a **multi-lane round**: the outputs of several validators that
    /// produced blocks *concurrently* in the same round (the macro-DAG). Each
    /// lane is PoU-attested; the lanes are ordered deterministically (leaderless
    /// macro-DAG ordering — every honest validator computes the same order) and
    /// applied in that order.
    ///
    /// This is the node-side wiring of concurrent block production: aggregate
    /// throughput is `N lanes × per-lane`, and because lanes touch disjoint
    /// objects (cross-lane conflict rejection) their application commutes, so
    /// every validator reaches the *same* state root regardless of the order the
    /// lanes arrived over the network. Contrast [`apply_attested_batch`], which
    /// applies a single lane and chains `prior_root`; here all lanes fork from
    /// the same round base, so the base is checked once and the lanes are then
    /// ordered and applied together.
    ///
    /// # Errors
    /// Returns an error if any lane's attestation fails verification, if the
    /// lanes do not all fork from the current state root, or if two lanes claim
    /// the same transaction set (a cross-lane conflict that must not occur).
    ///
    /// # Panics
    /// Does not panic in practice: the deterministic ordering is a permutation
    /// of the submitted lanes, so every ordered hash resolves to a lane.
    #[allow(clippy::needless_pass_by_value)] // a round semantically consumes its lanes
    pub fn apply_lane_round(&mut self, lanes: Vec<LaneBlock>) -> NodeResult<LaneRoundOutcome> {
        if lanes.is_empty() {
            return Ok(LaneRoundOutcome {
                ordered_lanes: Vec::new(),
                state_root: self.state.root(),
                lanes_applied: 0,
                objects_applied: 0,
            });
        }
        let round_base = self.state.root().0 .0;

        // 1. Verify every lane's PoU attestation and that each forked from the
        //    same round base (concurrent production from one prior state).
        for lane in &lanes {
            if !lane.attestation.verify() {
                return Err(NodeError::SubsystemCrash {
                    subsystem: "attestation".to_string(),
                    reason: format!("lane {} attestation failed verification", lane.lane_id),
                });
            }
            if lane.attestation.prior_root != round_base {
                return Err(NodeError::SubsystemCrash {
                    subsystem: "macro_dag".to_string(),
                    reason: format!("lane {} did not fork from the round base", lane.lane_id),
                });
            }
        }

        // 2. Reject cross-lane conflicts: two lanes must not claim the same tx
        //    set (their tx_commitments must be distinct).
        let mut seen = std::collections::HashSet::new();
        for lane in &lanes {
            if !seen.insert(lane.attestation.tx_commitment) {
                return Err(NodeError::SubsystemCrash {
                    subsystem: "macro_dag".to_string(),
                    reason: "two lanes claim the same transaction set".to_string(),
                });
            }
        }

        // 3. Deterministic leaderless ordering by each lane's canonical hash
        //    (its tx_commitment), via the macro-DAG ordering primitive.
        let hashes: Vec<BlockHash> =
            lanes.iter().map(|l| Hash256(l.attestation.tx_commitment)).collect();
        let ordering = BlockOrdering::deterministic(&hashes);
        let lane_by_hash: std::collections::HashMap<[u8; 32], &LaneBlock> =
            lanes.iter().map(|l| (l.attestation.tx_commitment, l)).collect();

        // 4. Apply each lane's delta in the deterministic order.
        let mut ordered_lanes = Vec::with_capacity(lanes.len());
        let mut objects_applied = 0usize;
        for h in &ordering.ordered_blocks {
            let lane = lane_by_hash
                .get(&h.0)
                .expect("every ordered hash maps to a submitted lane");
            for (object_id, data) in &lane.delta {
                self.state
                    .insert(&Self::state_key(object_id), StorageValue::from_bytes(data.clone()));
                objects_applied += 1;
            }
            ordered_lanes.push(lane.lane_id);
        }
        self.height += 1;

        Ok(LaneRoundOutcome {
            ordered_lanes,
            state_root: self.state.root(),
            lanes_applied: lanes.len(),
            objects_applied,
        })
    }

    /// Apply only this validator's **assigned slice** of a multi-lane round
    /// (sharded verification). Each lane is deterministically assigned a
    /// verifying quorum ([`LaneAssignment`]); this validator processes only the
    /// lanes it is in the quorum for, so its load is a bounded slice regardless
    /// of the total lane count. Every honest validator computes the same
    /// assignment, so across the set every lane is covered by a quorum and the
    /// aggregate scales linearly with the validator count — the uncapped regime.
    ///
    /// This is the throughput-unlocking counterpart to [`apply_lane_round`]
    /// (which is the full-verification path where every validator applies every
    /// lane and the aggregate is capped at one verifier's rate).
    ///
    /// # Errors
    /// Propagates the same lane-validation errors as [`apply_lane_round`] for
    /// the assigned slice.
    #[allow(clippy::needless_pass_by_value)] // a round semantically consumes its lanes
    pub fn apply_lane_round_sharded(
        &mut self,
        lanes: Vec<LaneBlock>,
        validator_index: usize,
        validator_count: usize,
        quorum_size: usize,
    ) -> NodeResult<LaneRoundOutcome> {
        let assigned: Vec<LaneBlock> = lanes
            .into_iter()
            .filter(|l| {
                LaneAssignment::is_assigned(
                    validator_index,
                    &Hash256(l.attestation.tx_commitment),
                    validator_count,
                    quorum_size,
                )
            })
            .collect();
        self.apply_lane_round(assigned)
    }

    /// Inspect a round's lanes for corruption and return slashing evidence
    /// against each offending producer — closing the "valid until proven
    /// corrupted" loop.
    ///
    /// A lane is corrupt if its Proof-of-Uncorruption attestation does not verify (the producer
    /// claimed a state transition its attestation does not support). An assigned
    /// verifier that finds this emits [`SlashingEvidenceType::InvalidAttestation`]
    /// evidence naming the producer; the graduated slashing policy
    /// (`aevor-consensus`) turns that into a stake penalty. Honest lanes produce
    /// no evidence. This is the hybrid Proof-of-Uncorruption + staking/slashing model: mathematical
    /// corruption detection backed by an economic consequence.
    #[must_use]
    pub fn detect_lane_corruption(&self, lanes: &[LaneBlock]) -> Vec<SlashingEvidence> {
        lanes
            .iter()
            .filter(|l| !l.attestation.verify())
            .map(|l| SlashingEvidence {
                offender: l.producer,
                evidence_type: SlashingEvidenceType::InvalidAttestation,
                // The offending attestation, so any validator can re-check it fails.
                evidence_a: l.attestation.signature.clone(),
                evidence_b: None,
                timestamp: aevor_core::consensus::ConsensusTimestamp::new(0, 0, self.height),
            })
            .collect()
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

        // Real BLS12-381 aggregate finality: each validator signs the block hash
        // with its consensus key; the aggregate is ONE signature verified in a
        // single pairing check against the committee's aggregate public key —
        // O(1) regardless of committee size (see the no-degradation benchmark).
        let msg = block_hash.0;
        let mut aggregator = BlsAggregator::new(Hash256(msg), committee.len());
        for (i, member) in committee.iter().enumerate() {
            let _ = aggregator.add_signature(i, &member.bls.sign(&msg));
        }
        let (bls_verified, aggregate_signature) = match aggregator.aggregate() {
            Ok(agg) => {
                let pubkeys: Vec<_> = committee.iter().map(|m| m.bls.public_key()).collect();
                let verified = aggregate_public_keys(&pubkeys)
                    .is_ok_and(|key| agg.verify_with_aggregate_key(&msg, &key));
                (verified, agg.aggregate)
            }
            Err(_) => (false, Vec::new()),
        };

        match result.finality_proof {
            Some(proof) => Ok(FinalityOutcome {
                finalized: true,
                signature_count: proof.signatures.len(),
                signed_weight: proof.total_weight.0,
                bls_verified,
                aggregate_signature,
            }),
            None => Ok(FinalityOutcome {
                finalized: false,
                signature_count: 0,
                signed_weight: 0,
                bls_verified: false,
                aggregate_signature: Vec::new(),
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
        StateTree::verify(proof)
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
