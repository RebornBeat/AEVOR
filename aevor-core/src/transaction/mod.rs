//! # Transaction Types
//!
//! The fundamental unit of work in AEVOR: transactions, their inputs/outputs,
//! signatures, receipts, and status tracking.

use serde::{Deserialize, Serialize};
use crate::primitives::{
    Address, Amount, ChainId, GasAmount, GasPrice, Hash256,
    Nonce, ObjectId, PublicKey, Signature, TransactionHash,
};
use crate::consensus::SecurityLevel;
use crate::privacy::PrivacyLevel;

// ============================================================
// TRANSACTION TYPE
// ============================================================

/// Classification of AEVOR transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionType {
    /// Transfer tokens between accounts.
    Transfer,
    /// Deploy a new smart contract.
    Deploy,
    /// Call a deployed smart contract function.
    Call,
    /// A Move-language transaction (may contain multiple operations).
    Move,
    /// Stake tokens with a validator.
    Stake,
    /// Unstake tokens from a validator.
    Unstake,
    /// Submit a governance proposal.
    Governance,
    /// Cross-chain bridge operation.
    Bridge,
    /// Create or manage a name service entry.
    NameService,
    /// A batch of operations executed atomically.
    Batch,
}

impl TransactionType {
    /// Returns `true` if this transaction type can modify smart contract state.
    pub fn can_modify_contract_state(&self) -> bool {
        matches!(self, Self::Deploy | Self::Call | Self::Move | Self::Batch)
    }

    /// Returns `true` if this transaction type requires TEE execution.
    pub fn requires_tee_for_privacy(&self) -> bool {
        false // Privacy requirement depends on the objects, not the type
    }
}

impl std::fmt::Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transfer => write!(f, "Transfer"),
            Self::Deploy => write!(f, "Deploy"),
            Self::Call => write!(f, "Call"),
            Self::Move => write!(f, "Move"),
            Self::Stake => write!(f, "Stake"),
            Self::Unstake => write!(f, "Unstake"),
            Self::Governance => write!(f, "Governance"),
            Self::Bridge => write!(f, "Bridge"),
            Self::NameService => write!(f, "NameService"),
            Self::Batch => write!(f, "Batch"),
        }
    }
}

// ============================================================
// TRANSACTION INPUT
// ============================================================

/// An input to a transaction — object being consumed or modified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInput {
    /// The object being used as input.
    pub object_id: ObjectId,
    /// Expected version of the object (for optimistic concurrency control).
    pub expected_version: u64,
    /// Content hash of the object at the expected version.
    pub content_hash: Hash256,
    /// How this input is being used.
    pub access_type: InputAccessType,
}

/// How a transaction accesses an input object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InputAccessType {
    /// Read-only access (object is not modified).
    Read,
    /// Read-write access (object will be modified).
    ReadWrite,
    /// Consume (object will be deleted after the transaction).
    Consume,
}

// ============================================================
// TRANSACTION OUTPUT
// ============================================================

/// An output of a transaction — object being created or modified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOutput {
    /// Identifier for the output object (may be new or existing).
    pub object_id: ObjectId,
    /// Serialized object data.
    pub data: Vec<u8>,
    /// Privacy level of this output.
    pub privacy_level: PrivacyLevel,
    /// Address that owns this output.
    pub owner: Address,
    /// Whether this output is newly created (vs modified from an input).
    pub is_new: bool,
}

// ============================================================
// TRANSACTION (BODY)
// ============================================================

/// The unsigned body of a transaction.
///
/// Contains all the information needed to execute the transaction.
/// The body is what gets signed to produce a `SignedTransaction`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique hash of this transaction (computed from body).
    pub hash: TransactionHash,
    /// Chain this transaction is for (prevents cross-chain replay).
    pub chain_id: ChainId,
    /// Transaction type.
    pub tx_type: TransactionType,
    /// Address that is initiating this transaction.
    pub sender: Address,
    /// Sender's public key (for signature verification).
    pub sender_public_key: PublicKey,
    /// Sender's current nonce (prevents replay attacks).
    pub nonce: Nonce,
    /// Objects being consumed or read by this transaction.
    pub inputs: Vec<TransactionInput>,
    /// Expected outputs of this transaction.
    pub outputs: Vec<TransactionOutput>,
    /// Gas limit for execution.
    pub gas_limit: GasAmount,
    /// Maximum gas price acceptable.
    pub max_gas_price: GasPrice,
    /// Token amount transferred (for Transfer transactions).
    pub value: Amount,
    /// Encoded payload (contract bytecode, call data, etc.).
    pub payload: Vec<u8>,
    /// Security level required for this transaction's finality.
    pub required_security_level: SecurityLevel,
    /// Privacy level for this transaction's execution.
    pub privacy_level: PrivacyLevel,
    /// Additional metadata (application-defined key-value pairs).
    pub metadata: Vec<(String, Vec<u8>)>,
}

impl Transaction {
    /// Returns `true` if this transaction requires TEE execution.
    pub fn requires_tee(&self) -> bool {
        self.privacy_level.requires_tee()
    }

    /// Returns the total declared read set (from inputs).
    pub fn declared_read_set(&self) -> Vec<ObjectId> {
        self.inputs
            .iter()
            .filter(|i| !matches!(i.access_type, InputAccessType::ReadWrite | InputAccessType::Consume))
            .map(|i| i.object_id)
            .collect()
    }

    /// Returns the total declared write set (from inputs + outputs).
    pub fn declared_write_set(&self) -> Vec<ObjectId> {
        let mut writes: Vec<ObjectId> = self.inputs
            .iter()
            .filter(|i| matches!(i.access_type, InputAccessType::ReadWrite | InputAccessType::Consume))
            .map(|i| i.object_id)
            .collect();
        for output in &self.outputs {
            if !output.is_new {
                writes.push(output.object_id);
            }
        }
        writes
    }
}

// ============================================================
// SIGNED TRANSACTION
// ============================================================

/// A transaction with its cryptographic signature(s).
///
/// Signature coverage: `Ed25519(BLAKE3(canonical_transaction_bytes))`
/// using the sender's key. Additional signatures may be present for
/// multi-sig transactions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The unsigned transaction body.
    pub transaction: Transaction,
    /// Primary signature from the transaction sender.
    pub signature: Signature,
    /// Additional signatures for multi-signature transactions.
    pub multi_signatures: Vec<Signature>,
    /// Zero-knowledge proof if the transaction uses private inputs.
    pub privacy_proof: Option<crate::crypto::ZeroKnowledgeProof>,
}

impl SignedTransaction {
    /// The transaction's unique hash.
    pub fn hash(&self) -> TransactionHash {
        self.transaction.hash
    }

    /// The sender's address.
    pub fn sender(&self) -> Address {
        self.transaction.sender
    }

    /// Returns `true` if this is a multi-signature transaction.
    pub fn is_multi_sig(&self) -> bool {
        !self.multi_signatures.is_empty()
    }
}

// ============================================================
// TRANSACTION STATUS
// ============================================================

/// The lifecycle status of a submitted transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Received and validated by the node, pending inclusion in DAG.
    Pending,
    /// Included in the Micro-DAG, awaiting finality.
    Included,
    /// Achieved Minimal security level finality (20–50ms).
    FinalizedMinimal,
    /// Achieved Basic security level finality (100–200ms).
    FinalizedBasic,
    /// Achieved Strong security level finality (500–800ms).
    FinalizedStrong,
    /// Achieved Full security level finality (<1s).
    FinalizedFull,
    /// Execution failed — state changes rolled back.
    Failed,
    /// Dropped from the mempool (gas too low, nonce too old, etc.).
    Dropped,
}

impl TransactionStatus {
    /// Returns `true` if the transaction has reached any finality level.
    pub fn is_finalized(&self) -> bool {
        matches!(
            self,
            Self::FinalizedMinimal
                | Self::FinalizedBasic
                | Self::FinalizedStrong
                | Self::FinalizedFull
        )
    }

    /// Returns `true` if the transaction is still in-flight (not finalized, failed, or dropped).
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending | Self::Included)
    }

    /// Returns `true` if the transaction can be considered complete (success or failure).
    pub fn is_complete(&self) -> bool {
        !self.is_pending()
    }

    /// The security level achieved, if any.
    pub fn achieved_security_level(&self) -> Option<SecurityLevel> {
        match self {
            Self::FinalizedMinimal => Some(SecurityLevel::Minimal),
            Self::FinalizedBasic => Some(SecurityLevel::Basic),
            Self::FinalizedStrong => Some(SecurityLevel::Strong),
            Self::FinalizedFull => Some(SecurityLevel::Full),
            _ => None,
        }
    }
}

// ============================================================
// TRANSACTION RECEIPT
// ============================================================

/// The receipt produced after a transaction is executed and finalized.
///
/// Contains all information needed to verify that a transaction was
/// executed correctly: the execution result, state changes, gas used,
/// and the finality proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Hash of the transaction this is a receipt for.
    pub transaction_hash: TransactionHash,
    /// Final execution status.
    pub status: TransactionStatus,
    /// Gas consumed by this execution.
    pub gas_consumed: GasAmount,
    /// Actual fee paid.
    pub fee_paid: Amount,
    /// State changes produced by execution.
    pub state_changes: Vec<crate::execution::StateChange>,
    /// Events emitted during execution.
    pub events: Vec<crate::execution::ExecutionEvent>,
    /// Return value from contract call (if any).
    pub return_data: Vec<u8>,
    /// Error message if execution failed.
    pub error: Option<String>,
    /// Block height the transaction was included in.
    pub block_height: crate::primitives::BlockHeight,
    /// Consensus round the transaction was finalized in.
    pub finalized_round: u64,
    /// Finality proof for this transaction.
    pub finality_proof: Option<crate::consensus::FinalityProof>,
    /// TEE attestation if execution used TEE.
    pub tee_attestation: Option<crate::consensus::ExecutionAttestation>,
}

impl TransactionReceipt {
    /// Returns `true` if the transaction succeeded.
    pub fn is_success(&self) -> bool {
        !matches!(self.status, TransactionStatus::Failed | TransactionStatus::Dropped)
            && self.error.is_none()
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_status_finality_progression() {
        assert!(!TransactionStatus::Pending.is_finalized());
        assert!(!TransactionStatus::Included.is_finalized());
        assert!(TransactionStatus::FinalizedMinimal.is_finalized());
        assert!(TransactionStatus::FinalizedFull.is_finalized());
    }

    #[test]
    fn transaction_status_pending_checks() {
        assert!(TransactionStatus::Pending.is_pending());
        assert!(TransactionStatus::Included.is_pending());
        assert!(!TransactionStatus::FinalizedBasic.is_pending());
    }

    #[test]
    fn transaction_status_security_level() {
        assert_eq!(
            TransactionStatus::FinalizedFull.achieved_security_level(),
            Some(SecurityLevel::Full)
        );
        assert_eq!(
            TransactionStatus::Pending.achieved_security_level(),
            None
        );
    }

    #[test]
    fn transaction_type_contract_modification() {
        assert!(TransactionType::Call.can_modify_contract_state());
        assert!(TransactionType::Deploy.can_modify_contract_state());
        assert!(!TransactionType::Transfer.can_modify_contract_state());
        assert!(!TransactionType::Stake.can_modify_contract_state());
    }

    #[test]
    fn signed_transaction_is_not_multi_sig_by_default() {
        let tx = Transaction {
            hash: Hash256::ZERO,
            chain_id: ChainId::MAINNET,
            tx_type: TransactionType::Transfer,
            sender: Address::ZERO,
            sender_public_key: PublicKey([0u8; 32]),
            nonce: Nonce::INITIAL,
            inputs: vec![],
            outputs: vec![],
            gas_limit: GasAmount::from_u64(21_000),
            max_gas_price: GasPrice::ZERO,
            value: Amount::ZERO,
            payload: vec![],
            required_security_level: SecurityLevel::Basic,
            privacy_level: PrivacyLevel::Public,
            metadata: vec![],
        };
        let signed = SignedTransaction {
            transaction: tx,
            signature: Signature::ZERO,
            multi_signatures: vec![],
            privacy_proof: None,
        };
        assert!(!signed.is_multi_sig());
    }
}
