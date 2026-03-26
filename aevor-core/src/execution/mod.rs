//! # Execution Context Types
//!
//! Types representing the execution lifecycle in AEVOR's parallel VM:
//! execution contexts, object access tracking, parallel execution plans,
//! TEE execution contexts, and execution results.
//!
//! These types are the interface layer between the DAG scheduler and the VM —
//! they define what information flows into an execution and what comes out.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::primitives::{
    Address, BlockHeight, GasAmount, Hash256, ObjectId, TransactionHash,
};
use crate::privacy::PrivacyLevel;
use crate::consensus::{ConsensusTimestamp, SecurityLevel};

// ============================================================
// EXECUTION ENVIRONMENT
// ============================================================

/// The execution environment available to a smart contract or transaction.
///
/// Contains read-only blockchain context that the VM provides to every
/// execution — block information, network state, and available services.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEnvironment {
    /// Current block height.
    pub block_height: BlockHeight,
    /// Consensus timestamp of the current block.
    pub timestamp: ConsensusTimestamp,
    /// Chain identifier.
    pub chain_id: crate::primitives::ChainId,
    /// Whether this execution is happening inside a TEE enclave.
    pub in_tee: bool,
    /// Active TEE platforms available for this execution.
    pub available_tee_platforms: Vec<crate::tee::TeePlatform>,
    /// Maximum gas available for this execution.
    pub gas_limit: GasAmount,
    /// Current base fee per gas unit.
    pub base_fee: crate::primitives::GasPrice,
}

// ============================================================
// EXECUTION CONTEXT
// ============================================================

/// Context for a single transaction or contract execution.
///
/// Combines the execution environment with transaction-specific information:
/// the sender, value transferred, input data, and object access permissions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Transaction being executed.
    pub transaction_hash: TransactionHash,
    /// Address that initiated this execution.
    pub sender: Address,
    /// Address of the contract being called (None for transfers/deploy).
    pub receiver: Option<Address>,
    /// Token amount transferred with this execution.
    pub value: crate::primitives::Amount,
    /// Input data (function call arguments, encoded).
    pub input_data: Vec<u8>,
    /// Available execution environment.
    pub environment: ExecutionEnvironment,
    /// Privacy level of this execution context.
    pub privacy_level: PrivacyLevel,
    /// Gas limit for this execution.
    pub gas_limit: GasAmount,
    /// Object access tracker for this execution.
    pub access_tracker: ObjectAccessTracker,
    /// Execution lane in the parallel scheduler.
    pub execution_lane: ExecutionLane,
    /// TEE context if executing inside a TEE.
    pub tee_context: Option<TeeExecutionContext>,
}

impl ExecutionContext {
    /// Returns `true` if this execution is happening inside a TEE enclave.
    pub fn is_in_tee(&self) -> bool {
        self.tee_context.is_some()
    }

    /// Returns `true` if this execution requires privacy-preserving computation.
    pub fn requires_privacy(&self) -> bool {
        self.privacy_level.requires_tee()
    }
}

// ============================================================
// TEE EXECUTION CONTEXT
// ============================================================

/// TEE-specific execution context for private computations.
///
/// Provides the TEE platform details, attestation nonce, and isolation
/// boundary for executions that require hardware-enforced confidentiality.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeExecutionContext {
    /// The TEE platform this execution runs on.
    pub platform: crate::tee::TeePlatform,
    /// Attestation nonce for this execution (binds result to TEE).
    pub attestation_nonce: [u8; 32],
    /// Isolation boundary identifier.
    pub isolation_id: Hash256,
    /// Whether anti-snooping protection is active.
    pub anti_snooping: bool,
    /// Memory range allocated for this execution.
    pub memory_range: Option<crate::tee::MemoryRange>,
}

// ============================================================
// OBJECT ACCESS TRACKER
// ============================================================

/// Tracks all object reads and writes during an execution.
///
/// Used by the parallel scheduler to verify that an execution's actual
/// access pattern matches its declared conflict set, and to detect
/// any post-execution conflict resolution requirements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObjectAccessTracker {
    /// Objects that were read during this execution.
    pub reads: Vec<ObjectId>,
    /// Objects that were written during this execution.
    pub writes: Vec<ObjectId>,
    /// Objects that were created during this execution.
    pub created: Vec<ObjectId>,
    /// Objects that were deleted during this execution.
    pub deleted: Vec<ObjectId>,
    /// Whether any access exceeded the declared conflict set.
    pub undeclared_access_detected: bool,
}

impl ObjectAccessTracker {
    /// Record a read access.
    pub fn record_read(&mut self, id: ObjectId) {
        if !self.reads.contains(&id) {
            self.reads.push(id);
        }
    }

    /// Record a write access.
    pub fn record_write(&mut self, id: ObjectId) {
        if !self.writes.contains(&id) {
            self.writes.push(id);
        }
    }

    /// Record an object creation.
    pub fn record_create(&mut self, id: ObjectId) {
        self.created.push(id);
    }

    /// Record an object deletion.
    pub fn record_delete(&mut self, id: ObjectId) {
        self.deleted.push(id);
        self.writes.retain(|w| w != &id);
    }

    /// Returns `true` if this execution has no object interactions.
    pub fn is_empty(&self) -> bool {
        self.reads.is_empty()
            && self.writes.is_empty()
            && self.created.is_empty()
            && self.deleted.is_empty()
    }

    /// Returns the combined set of all mutated object IDs.
    pub fn all_mutations(&self) -> Vec<ObjectId> {
        let mut mutations = self.writes.clone();
        mutations.extend_from_slice(&self.created);
        mutations.extend_from_slice(&self.deleted);
        mutations.sort_by_key(|id| id.as_bytes().to_vec());
        mutations.dedup();
        mutations
    }
}

// ============================================================
// OBJECT DEPENDENCY
// ============================================================

/// A dependency relationship between two objects in an execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectDependency {
    /// The object being depended on.
    pub dependency: ObjectId,
    /// The object that has the dependency.
    pub dependent: ObjectId,
    /// Type of dependency.
    pub dependency_type: DependencyType,
}

/// Classification of object dependency types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DependencyType {
    /// Read-after-write dependency (dependent reads what dependency writes).
    ReadAfterWrite,
    /// Write-after-read dependency (dependent writes what dependency reads).
    WriteAfterRead,
    /// Write-after-write dependency (both write the same object).
    WriteAfterWrite,
    /// Causal dependency (dependent must complete before dependency).
    Causal,
}

// ============================================================
// EXECUTION LANE
// ============================================================

/// Identifies a parallel execution lane in the DAG scheduler.
///
/// Transactions in the same lane are serialized; transactions in different
/// lanes can execute concurrently. The scheduler assigns lanes based on
/// the conflict graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct ExecutionLane(pub u32);

impl ExecutionLane {
    /// The default sequential lane.
    pub const SEQUENTIAL: Self = Self(0);

    /// Create a lane identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Raw lane ID.
    pub fn id(&self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for ExecutionLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lane:{}", self.0)
    }
}

// ============================================================
// EXECUTION PATH
// ============================================================

/// A causal execution path through the DAG.
///
/// Represents a sequence of causally-ordered operations that must
/// be executed in order, even though other paths execute in parallel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPath {
    /// Ordered list of transactions in this path.
    pub transactions: Vec<TransactionHash>,
    /// Lane assigned to this path.
    pub lane: ExecutionLane,
    /// Dependencies on other paths (must complete before this path proceeds).
    pub path_dependencies: Vec<ExecutionLane>,
}

// ============================================================
// PARALLEL EXECUTION PLAN
// ============================================================

/// A complete parallel execution plan for a set of transactions.
///
/// Produced by the DAG scheduler before execution begins. Contains all
/// information needed to execute transactions in parallel with maximum
/// throughput while respecting all data dependencies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelExecutionPlan {
    /// All transactions to execute, grouped by lane.
    pub lanes: HashMap<u32, Vec<TransactionHash>>,
    /// Dependency graph between lanes.
    pub lane_dependencies: HashMap<u32, Vec<u32>>,
    /// Objects that require TEE execution.
    pub tee_objects: Vec<ObjectId>,
    /// Maximum achievable parallelism (number of concurrent lanes).
    pub max_parallelism: usize,
    /// Total number of transactions in this plan.
    pub transaction_count: usize,
    /// Estimated execution time in milliseconds.
    pub estimated_execution_ms: u64,
}

impl ParallelExecutionPlan {
    /// Returns `true` if this plan has any parallel lanes.
    pub fn is_parallel(&self) -> bool {
        self.lanes.len() > 1
    }

    /// Returns the number of execution lanes.
    pub fn lane_count(&self) -> usize {
        self.lanes.len()
    }
}

// ============================================================
// STATE CHANGE
// ============================================================

/// A single state change produced by an execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateChange {
    /// The object that changed.
    pub object_id: ObjectId,
    /// Previous content hash (None if object was created).
    pub previous_hash: Option<Hash256>,
    /// New content hash (None if object was deleted).
    pub new_hash: Option<Hash256>,
    /// The actual value after change (None for deletions or private objects).
    pub new_value: Option<Vec<u8>>,
    /// Privacy level of this state change.
    pub privacy_level: PrivacyLevel,
}

impl StateChange {
    /// Returns `true` if this is an object creation.
    pub fn is_creation(&self) -> bool {
        self.previous_hash.is_none() && self.new_hash.is_some()
    }

    /// Returns `true` if this is an object deletion.
    pub fn is_deletion(&self) -> bool {
        self.previous_hash.is_some() && self.new_hash.is_none()
    }

    /// Returns `true` if this is an object mutation.
    pub fn is_mutation(&self) -> bool {
        self.previous_hash.is_some() && self.new_hash.is_some()
    }
}

// ============================================================
// EXECUTION EVENT
// ============================================================

/// An event emitted by a smart contract during execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEvent {
    /// Address of the contract that emitted the event.
    pub emitter: Address,
    /// Event topic (identifies the event type).
    pub topic: Hash256,
    /// Event data payload.
    pub data: Vec<u8>,
    /// Privacy level of this event.
    pub privacy_level: PrivacyLevel,
    /// Sequence number within this execution.
    pub sequence: u32,
}

// ============================================================
// EXECUTION LOG
// ============================================================

/// The complete log of events emitted during an execution.
///
/// The bloom filter is stored as a `Vec<u8>` (256 bytes) for serde compatibility —
/// serde only implements Serialize/Deserialize for arrays up to [u8; 32].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLog {
    /// Events emitted in order.
    pub events: Vec<ExecutionEvent>,
    /// Bloom filter over event topics for fast filtering (256 bytes = 2048 bits).
    pub topics_bloom: Vec<u8>,
}

impl Default for ExecutionLog {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            topics_bloom: vec![0u8; 256],
        }
    }
}

impl ExecutionLog {
    /// Add an event to the log.
    pub fn push_event(&mut self, event: ExecutionEvent) {
        // Ensure bloom filter is full size.
        if self.topics_bloom.len() < 256 {
            self.topics_bloom.resize(256, 0u8);
        }
        // Update bloom filter with three hash positions.
        let hash = event.topic.0;
        for i in 0..3 {
            let bit = u64::from_be_bytes(hash[i*8..(i+1)*8].try_into().unwrap()) % 2048;
            let byte_idx = (bit / 8) as usize;
            let bit_idx = (bit % 8) as u8;
            self.topics_bloom[byte_idx] |= 1 << bit_idx;
        }
        self.events.push(event);
    }

    /// Returns `true` if the bloom filter suggests `topic` may be in the log.
    pub fn may_contain_topic(&self, topic: &Hash256) -> bool {
        if self.topics_bloom.len() < 256 {
            return false;
        }
        let hash = topic.0;
        for i in 0..3 {
            let bit = u64::from_be_bytes(hash[i*8..(i+1)*8].try_into().unwrap()) % 2048;
            let byte_idx = (bit / 8) as usize;
            let bit_idx = (bit % 8) as u8;
            if self.topics_bloom[byte_idx] & (1 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }
}

// ============================================================
// CONTRACT EXECUTION
// ============================================================

/// Input to a contract call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractExecution {
    /// Address of the contract being called.
    pub contract: Address,
    /// Function selector or name.
    pub function: String,
    /// Encoded arguments.
    pub arguments: Vec<u8>,
    /// Gas limit for this call.
    pub gas_limit: GasAmount,
    /// Privacy level required.
    pub privacy_level: PrivacyLevel,
}

// ============================================================
// TRANSACTION EXECUTION
// ============================================================

/// Complete input description for executing a transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionExecution {
    /// The transaction hash being executed.
    pub transaction_hash: TransactionHash,
    /// Pre-built execution context.
    pub context: ExecutionContext,
    /// Execution plan entry for this transaction.
    pub lane: ExecutionLane,
    /// Security level required for this execution.
    pub security_level: SecurityLevel,
}

// ============================================================
// EXECUTION RESULT
// ============================================================

/// The result of executing a transaction or contract call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Whether execution succeeded.
    pub success: bool,
    /// Gas consumed by this execution.
    pub gas_consumed: GasAmount,
    /// State changes produced by this execution.
    pub state_changes: Vec<StateChange>,
    /// Events emitted by this execution.
    pub log: ExecutionLog,
    /// Return value (encoded).
    pub return_data: Vec<u8>,
    /// Error description if execution failed.
    pub error: Option<String>,
    /// TEE attestation if this execution ran inside a TEE.
    pub tee_attestation: Option<crate::consensus::ExecutionAttestation>,
    /// Objects accessed during execution.
    pub access_tracker: ObjectAccessTracker,
}

impl ExecutionResult {
    /// Create a successful execution result.
    pub fn success(
        gas_consumed: GasAmount,
        state_changes: Vec<StateChange>,
        log: ExecutionLog,
        return_data: Vec<u8>,
    ) -> Self {
        Self {
            success: true,
            gas_consumed,
            state_changes,
            log,
            return_data,
            error: None,
            tee_attestation: None,
            access_tracker: ObjectAccessTracker::default(),
        }
    }

    /// Create a failed execution result.
    pub fn failure(gas_consumed: GasAmount, error: impl Into<String>) -> Self {
        Self {
            success: false,
            gas_consumed,
            state_changes: Vec::new(),
            log: ExecutionLog::default(),
            return_data: Vec::new(),
            error: Some(error.into()),
            tee_attestation: None,
            access_tracker: ObjectAccessTracker::default(),
        }
    }

    /// Returns `true` if execution succeeded.
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Total number of state changes.
    pub fn change_count(&self) -> usize {
        self.state_changes.len()
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Hash256;

    #[test]
    fn access_tracker_read_deduplication() {
        let id = ObjectId::from_hash(Hash256([1u8; 32]));
        let mut tracker = ObjectAccessTracker::default();
        tracker.record_read(id);
        tracker.record_read(id); // Duplicate
        assert_eq!(tracker.reads.len(), 1);
    }

    #[test]
    fn access_tracker_delete_removes_from_writes() {
        let id = ObjectId::from_hash(Hash256([2u8; 32]));
        let mut tracker = ObjectAccessTracker::default();
        tracker.record_write(id);
        tracker.record_delete(id);
        assert!(!tracker.writes.contains(&id));
        assert!(tracker.deleted.contains(&id));
    }

    #[test]
    fn execution_result_success_fields() {
        let r = ExecutionResult::success(
            GasAmount::from_u64(1000),
            vec![],
            ExecutionLog::default(),
            vec![42],
        );
        assert!(r.is_success());
        assert_eq!(r.return_data, vec![42]);
        assert!(r.error.is_none());
    }

    #[test]
    fn execution_result_failure_fields() {
        let r = ExecutionResult::failure(GasAmount::from_u64(500), "out of gas");
        assert!(!r.is_success());
        assert_eq!(r.error.as_deref(), Some("out of gas"));
        assert!(r.state_changes.is_empty());
    }

    #[test]
    fn parallel_plan_single_lane_not_parallel() {
        let mut lanes = HashMap::new();
        lanes.insert(0u32, vec![Hash256::ZERO]);
        let plan = ParallelExecutionPlan {
            lanes,
            lane_dependencies: HashMap::new(),
            tee_objects: vec![],
            max_parallelism: 1,
            transaction_count: 1,
            estimated_execution_ms: 10,
        };
        assert!(!plan.is_parallel());
    }

    #[test]
    fn state_change_creation_detection() {
        let change = StateChange {
            object_id: ObjectId::from_hash(Hash256::ZERO),
            previous_hash: None,
            new_hash: Some(Hash256([1u8; 32])),
            new_value: None,
            privacy_level: PrivacyLevel::Public,
        };
        assert!(change.is_creation());
        assert!(!change.is_deletion());
        assert!(!change.is_mutation());
    }

    #[test]
    fn execution_lane_sequential_is_zero() {
        assert_eq!(ExecutionLane::SEQUENTIAL.id(), 0);
    }
}
