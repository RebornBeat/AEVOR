use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use std::collections::HashMap;
use std::net::SocketAddr;
use async_trait::async_trait;

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::core::object::{Object, ObjectID};
use crate::crypto::signature::{Signature, SignatureAlgorithm};
use crate::error::{AevorError, Result};
use crate::consensus::security::SecurityLevel;
use crate::consensus::pou::UncorruptedChainData;
use crate::consensus::superposition::SuperpositionedState;

/// Protocol version supported by the node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolVersion {
    /// Version 1 - Dual-DAG PoU with Security Level Acceleration
    V1,
    
    /// Future version
    V2,
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolVersion::V1 => write!(f, "V1"),
            ProtocolVersion::V2 => write!(f, "V2"),
        }
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        ProtocolVersion::V1
    }
}

/// Types of messages supported by the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    /// Handshake message for establishing connections
    Handshake,
    
    /// Ping message to check node availability
    Ping,
    
    /// Pong response to a ping message
    Pong,
    
    /// Error message
    Error,
    
    /// Get a specific block by hash or height
    GetBlock,
    
    /// Block response
    Block,
    
    /// Get multiple blocks in a range
    GetBlocks,
    
    /// Multiple blocks response
    Blocks,
    
    /// Get a specific transaction by hash
    GetTransaction,
    
    /// Transaction response
    Transaction,
    
    /// Get a specific object by ID
    GetObject,
    
    /// Object response
    Object,
    
    /// Submit a new transaction to the network
    SubmitTransaction,
    
    /// Submit a new block to the network
    SubmitBlock,
    
    /// Chain status information
    ChainInfo,
    
    /// Request for peer addresses
    GetPeers,
    
    /// Peer addresses response
    Peers,
    
    /// Sync status information
    SyncStatus,
    
    /// Get validator set information
    GetValidatorSet,
    
    /// Validator set response
    ValidatorSet,
    
    /// Transaction validation result
    ValidationResult,
    
    /// Finality proof for a block
    FinalityProof,
    
    /// Uncorrupted chain data
    UncorruptedChain,
    
    /// Request for superpositioned states
    GetSuperpositionedStates,
    
    /// Superpositioned states response
    SuperpositionedStates,
    
    /// Security level confirmation for a transaction
    SecurityLevelConfirmation,
    
    /// BLS signature aggregate
    BLSSignatureAggregate,
    
    /// Network topology discovery
    TopologyDiscovery,
    
    /// Topology update
    TopologyUpdate,
    
    /// Get object states with proofs
    GetStateProof,
    
    /// State proof response
    StateProof,
    
    /// Request for chain data availability fragments
    GetDataAvailability,
    
    /// Data availability fragments response
    DataAvailability,
    
    /// TEE attestation for Proof of Uncorruption
    TEEAttestation,
    
    /// Custom message type
    Custom(u16),
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::Handshake => write!(f, "Handshake"),
            MessageType::Ping => write!(f, "Ping"),
            MessageType::Pong => write!(f, "Pong"),
            MessageType::Error => write!(f, "Error"),
            MessageType::GetBlock => write!(f, "GetBlock"),
            MessageType::Block => write!(f, "Block"),
            MessageType::GetBlocks => write!(f, "GetBlocks"),
            MessageType::Blocks => write!(f, "Blocks"),
            MessageType::GetTransaction => write!(f, "GetTransaction"),
            MessageType::Transaction => write!(f, "Transaction"),
            MessageType::GetObject => write!(f, "GetObject"),
            MessageType::Object => write!(f, "Object"),
            MessageType::SubmitTransaction => write!(f, "SubmitTransaction"),
            MessageType::SubmitBlock => write!(f, "SubmitBlock"),
            MessageType::ChainInfo => write!(f, "ChainInfo"),
            MessageType::GetPeers => write!(f, "GetPeers"),
            MessageType::Peers => write!(f, "Peers"),
            MessageType::SyncStatus => write!(f, "SyncStatus"),
            MessageType::GetValidatorSet => write!(f, "GetValidatorSet"),
            MessageType::ValidatorSet => write!(f, "ValidatorSet"),
            MessageType::ValidationResult => write!(f, "ValidationResult"),
            MessageType::FinalityProof => write!(f, "FinalityProof"),
            MessageType::UncorruptedChain => write!(f, "UncorruptedChain"),
            MessageType::GetSuperpositionedStates => write!(f, "GetSuperpositionedStates"),
            MessageType::SuperpositionedStates => write!(f, "SuperpositionedStates"),
            MessageType::SecurityLevelConfirmation => write!(f, "SecurityLevelConfirmation"),
            MessageType::BLSSignatureAggregate => write!(f, "BLSSignatureAggregate"),
            MessageType::TopologyDiscovery => write!(f, "TopologyDiscovery"),
            MessageType::TopologyUpdate => write!(f, "TopologyUpdate"),
            MessageType::GetStateProof => write!(f, "GetStateProof"),
            MessageType::StateProof => write!(f, "StateProof"),
            MessageType::GetDataAvailability => write!(f, "GetDataAvailability"),
            MessageType::DataAvailability => write!(f, "DataAvailability"),
            MessageType::TEEAttestation => write!(f, "TEEAttestation"),
            MessageType::Custom(id) => write!(f, "Custom-{}", id),
        }
    }
}

/// Network message for communication between nodes
#[derive(Clone, Serialize, Deserialize)]
pub struct Message {
    /// Protocol version
    pub version: ProtocolVersion,
    
    /// Message type
    pub message_type: MessageType,
    
    /// Message ID for request/response correlation
    pub id: u64,
    
    /// Message timestamp
    pub timestamp: u64,
    
    /// Sender node ID
    pub sender: Vec<u8>,
    
    /// Message payload
    pub payload: MessagePayload,
    
    /// Message signature
    pub signature: Option<Signature>,
}

impl Message {
    /// Creates a new message
    pub fn new(
        version: ProtocolVersion,
        message_type: MessageType,
        id: u64,
        sender: Vec<u8>,
        payload: MessagePayload,
    ) -> Self {
        Self {
            version,
            message_type,
            id,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sender,
            payload,
            signature: None,
        }
    }
    
    /// Signs the message with the sender's private key
    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        // Get the message hash
        let hash = self.hash();
        
        // Sign the hash
        let signature = Signature::sign(SignatureAlgorithm::ED25519, private_key, &hash)
            .map_err(|e| AevorError::crypto("Signing failed".into(), e.to_string(), None))?;
        
        self.signature = Some(signature);
        Ok(())
    }
    
    /// Verifies the message signature
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool> {
        // Check if the message is signed
        let signature = match &self.signature {
            Some(sig) => sig,
            None => return Ok(false),
        };
        
        // Get the message hash
        let hash = self.hash();
        
        // Verify the signature
        signature.verify(public_key, &hash)
            .map_err(|e| AevorError::crypto("Signature verification failed".into(), e.to_string(), None))
    }
    
    /// Calculates the hash of the message for signing
    pub fn hash(&self) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        
        // Hash message fields excluding signature
        hasher.update(&(self.version as u8).to_le_bytes());
        hasher.update(&(self.message_type as u8).to_le_bytes());
        hasher.update(&self.id.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.sender);
        
        // Hash payload
        let payload_bytes = bincode::serialize(&self.payload).unwrap_or_default();
        hasher.update(&payload_bytes);
        
        hasher.finalize().to_vec()
    }
    
    /// Serializes the message to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| AevorError::serialization(format!("Failed to serialize message: {}", e)))
    }
    
    /// Deserializes a message from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| AevorError::deserialization(format!("Failed to deserialize message: {}", e)))
    }
    
    /// Creates a handshake message
    pub fn create_handshake(
        id: u64,
        sender: Vec<u8>,
        data: HandshakeData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Handshake,
            id,
            sender,
            MessagePayload::Handshake(data),
        )
    }
    
    /// Creates a ping message
    pub fn create_ping(
        id: u64,
        sender: Vec<u8>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Ping,
            id,
            sender,
            MessagePayload::Empty,
        )
    }
    
    /// Creates a pong message in response to a ping
    pub fn create_pong(
        id: u64,
        sender: Vec<u8>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Pong,
            id,
            sender,
            MessagePayload::Empty,
        )
    }
    
    /// Creates an error message
    pub fn create_error(
        id: u64,
        sender: Vec<u8>,
        data: ErrorData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Error,
            id,
            sender,
            MessagePayload::Error(data),
        )
    }
    
    /// Creates a get block message
    pub fn create_get_block(
        id: u64,
        sender: Vec<u8>,
        data: BlockRequestData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::GetBlock,
            id,
            sender,
            MessagePayload::BlockRequest(data),
        )
    }
    
    /// Creates a block response message
    pub fn create_block_response(
        id: u64,
        sender: Vec<u8>,
        data: BlockResponseData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Block,
            id,
            sender,
            MessagePayload::BlockResponse(data),
        )
    }
    
    /// Creates a get blocks message
    pub fn create_get_blocks(
        id: u64,
        sender: Vec<u8>,
        data: BlocksRequestData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::GetBlocks,
            id,
            sender,
            MessagePayload::BlocksRequest(data),
        )
    }
    
    /// Creates a blocks response message
    pub fn create_blocks_response(
        id: u64,
        sender: Vec<u8>,
        data: BlocksResponseData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Blocks,
            id,
            sender,
            MessagePayload::BlocksResponse(data),
        )
    }
    
    /// Creates a get transaction message
    pub fn create_get_transaction(
        id: u64,
        sender: Vec<u8>,
        data: TransactionRequestData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::GetTransaction,
            id,
            sender,
            MessagePayload::TransactionRequest(data),
        )
    }
    
    /// Creates a transaction response message
    pub fn create_transaction_response(
        id: u64,
        sender: Vec<u8>,
        data: TransactionResponseData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Transaction,
            id,
            sender,
            MessagePayload::TransactionResponse(data),
        )
    }
    
    /// Creates a get object message
    pub fn create_get_object(
        id: u64,
        sender: Vec<u8>,
        data: ObjectRequestData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::GetObject,
            id,
            sender,
            MessagePayload::ObjectRequest(data),
        )
    }
    
    /// Creates an object response message
    pub fn create_object_response(
        id: u64,
        sender: Vec<u8>,
        data: ObjectResponseData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Object,
            id,
            sender,
            MessagePayload::ObjectResponse(data),
        )
    }
    
    /// Creates a submit transaction message
    pub fn create_submit_transaction(
        id: u64,
        sender: Vec<u8>,
        tx: Transaction,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::SubmitTransaction,
            id,
            sender,
            MessagePayload::Transaction(TransactionResponseData {
                transaction: Some(tx),
                error: None,
            }),
        )
    }
    
    /// Creates a submit block message
    pub fn create_submit_block(
        id: u64,
        sender: Vec<u8>,
        block: Block,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::SubmitBlock,
            id,
            sender,
            MessagePayload::BlockResponse(BlockResponseData {
                block: Some(block),
                error: None,
            }),
        )
    }
    
    /// Creates a chain info message
    pub fn create_chain_info(
        id: u64,
        sender: Vec<u8>,
        data: ChainInfoData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::ChainInfo,
            id,
            sender,
            MessagePayload::ChainInfo(data),
        )
    }
    
    /// Creates a get peers message
    pub fn create_get_peers(
        id: u64,
        sender: Vec<u8>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::GetPeers,
            id,
            sender,
            MessagePayload::Empty,
        )
    }
    
    /// Creates a peers response message
    pub fn create_peers_response(
        id: u64,
        sender: Vec<u8>,
        data: PeersData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Peers,
            id,
            sender,
            MessagePayload::Peers(data),
        )
    }
    
    /// Creates a sync status message
    pub fn create_sync_status(
        id: u64,
        sender: Vec<u8>,
        data: SyncStatusData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::SyncStatus,
            id,
            sender,
            MessagePayload::SyncStatus(data),
        )
    }
    
    /// Creates a get validator set message
    pub fn create_get_validator_set(
        id: u64,
        sender: Vec<u8>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::GetValidatorSet,
            id,
            sender,
            MessagePayload::Empty,
        )
    }
    
    /// Creates a validator set response message
    pub fn create_validator_set_response(
        id: u64,
        sender: Vec<u8>,
        data: ValidatorSetData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::ValidatorSet,
            id,
            sender,
            MessagePayload::ValidatorSet(data),
        )
    }
    
    /// Creates a validation result message
    pub fn create_validation_result(
        id: u64,
        sender: Vec<u8>,
        data: ValidationResultData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::ValidationResult,
            id,
            sender,
            MessagePayload::ValidationResult(data),
        )
    }
    
    /// Creates a finality proof message
    pub fn create_finality_proof(
        id: u64,
        sender: Vec<u8>,
        data: FinalityProofData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::FinalityProof,
            id,
            sender,
            MessagePayload::FinalityProof(data),
        )
    }
    
    /// Creates an uncorrupted chain message
    pub fn create_uncorrupted_chain(
        id: u64,
        sender: Vec<u8>,
        data: UncorruptedChainData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::UncorruptedChain,
            id,
            sender,
            MessagePayload::UncorruptedChain(data),
        )
    }
    
    /// Creates a get superpositioned states message
    pub fn create_get_superpositioned_states(
        id: u64,
        sender: Vec<u8>,
        data: SuperpositionedStatesRequestData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::GetSuperpositionedStates,
            id,
            sender,
            MessagePayload::SuperpositionedStatesRequest(data),
        )
    }
    
    /// Creates a superpositioned states response message
    pub fn create_superpositioned_states_response(
        id: u64,
        sender: Vec<u8>,
        data: SuperpositionedStatesResponseData,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::SuperpositionedStates,
            id,
            sender,
            MessagePayload::SuperpositionedStatesResponse(data),
        )
    }
    
    /// Creates a security level confirmation message
    pub fn create_security_level_confirmation(
        id: u64,
        sender: Vec<u8>,
        tx_hash: Vec<u8>,
        security_level: SecurityLevel,
        signature: Vec<u8>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::SecurityLevelConfirmation,
            id,
            sender,
            MessagePayload::SecurityLevelConfirmation(SecurityLevelConfirmationData {
                tx_hash,
                security_level,
                signature,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            }),
        )
    }
    
    /// Creates a BLS signature aggregate message
    pub fn create_bls_signature_aggregate(
        id: u64,
        sender: Vec<u8>,
        tx_hash: Vec<u8>,
        security_level: SecurityLevel,
        aggregate_signature: Vec<u8>,
        signers: Vec<Vec<u8>>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::BLSSignatureAggregate,
            id,
            sender,
            MessagePayload::BLSSignatureAggregate(BLSSignatureAggregateData {
                tx_hash,
                security_level,
                aggregate_signature,
                signers,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            }),
        )
    }
    
    /// Creates a topology discovery message
    pub fn create_topology_discovery(
        id: u64,
        sender: Vec<u8>,
        region: String,
        latency_map: HashMap<Vec<u8>, u32>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::TopologyDiscovery,
            id,
            sender,
            MessagePayload::TopologyDiscovery(TopologyDiscoveryData {
                region,
                latency_map,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            }),
        )
    }
    
    /// Creates a topology update message
    pub fn create_topology_update(
        id: u64,
        sender: Vec<u8>,
        region_updates: HashMap<String, Vec<PeerAddressData>>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::TopologyUpdate,
            id,
            sender,
            MessagePayload::TopologyUpdate(TopologyUpdateData {
                region_updates,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            }),
        )
    }
    
    /// Creates a get state proof message
    pub fn create_get_state_proof(
        id: u64,
        sender: Vec<u8>,
        object_ids: Vec<ObjectID>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::GetStateProof,
            id,
            sender,
            MessagePayload::StateProofRequest(StateProofRequestData {
                object_ids,
            }),
        )
    }
    
    /// Creates a state proof response message
    pub fn create_state_proof_response(
        id: u64,
        sender: Vec<u8>,
        proofs: HashMap<ObjectID, StateProofData>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::StateProof,
            id,
            sender,
            MessagePayload::StateProofResponse(StateProofResponseData {
                proofs,
            }),
        )
    }
    
    /// Creates a get data availability message
    pub fn create_get_data_availability(
        id: u64,
        sender: Vec<u8>,
        block_hash: Vec<u8>,
        shard_indices: Vec<u32>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::GetDataAvailability,
            id,
            sender,
            MessagePayload::DataAvailabilityRequest(DataAvailabilityRequestData {
                block_hash,
                shard_indices,
            }),
        )
    }
    
    /// Creates a data availability response message
    pub fn create_data_availability_response(
        id: u64,
        sender: Vec<u8>,
        block_hash: Vec<u8>,
        shards: HashMap<u32, Vec<u8>>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::DataAvailability,
            id,
            sender,
            MessagePayload::DataAvailabilityResponse(DataAvailabilityResponseData {
                block_hash,
                shards,
            }),
        )
    }
    
    /// Creates a TEE attestation message
    pub fn create_tee_attestation(
        id: u64,
        sender: Vec<u8>,
        tx_hash: Vec<u8>,
        attestation: Vec<u8>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::TEEAttestation,
            id,
            sender,
            MessagePayload::TEEAttestation(TEEAttestationData {
                tx_hash,
                attestation,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            }),
        )
    }
    
    /// Creates a custom message
    pub fn create_custom(
        id: u64,
        sender: Vec<u8>,
        type_id: u16,
        data: Vec<u8>,
    ) -> Self {
        Self::new(
            ProtocolVersion::V1,
            MessageType::Custom(type_id),
            id,
            sender,
            MessagePayload::Custom(data),
        )
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("version", &self.version)
            .field("message_type", &self.message_type)
            .field("id", &self.id)
            .field("timestamp", &self.timestamp)
            .field("sender", &hex::encode(&self.sender))
            .field("has_signature", &self.signature.is_some())
            .finish()
    }
}

/// Message payload variants for different message types
#[derive(Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    /// Empty payload
    Empty,
    
    /// Handshake data
    Handshake(HandshakeData),
    
    /// Error data
    Error(ErrorData),
    
    /// Block request data
    BlockRequest(BlockRequestData),
    
    /// Block response data
    BlockResponse(BlockResponseData),
    
    /// Blocks request data
    BlocksRequest(BlocksRequestData),
    
    /// Blocks response data
    BlocksResponse(BlocksResponseData),
    
    /// Transaction request data
    TransactionRequest(TransactionRequestData),
    
    /// Transaction response data
    TransactionResponse(TransactionResponseData),
    
    /// Object request data
    ObjectRequest(ObjectRequestData),
    
    /// Object response data
    ObjectResponse(ObjectResponseData),
    
    /// Chain info data
    ChainInfo(ChainInfoData),
    
    /// Peers data
    Peers(PeersData),
    
    /// Sync status data
    SyncStatus(SyncStatusData),
    
    /// Validator set data
    ValidatorSet(ValidatorSetData),
    
    /// Validation result data
    ValidationResult(ValidationResultData),
    
    /// Finality proof data
    FinalityProof(FinalityProofData),
    
    /// Uncorrupted chain data
    UncorruptedChain(UncorruptedChainData),
    
    /// Superpositioned states request data
    SuperpositionedStatesRequest(SuperpositionedStatesRequestData),
    
    /// Superpositioned states response data
    SuperpositionedStatesResponse(SuperpositionedStatesResponseData),
    
    /// Security level confirmation data
    SecurityLevelConfirmation(SecurityLevelConfirmationData),
    
    /// BLS signature aggregate data
    BLSSignatureAggregate(BLSSignatureAggregateData),
    
    /// Topology discovery data
    TopologyDiscovery(TopologyDiscoveryData),
    
    /// Topology update data
    TopologyUpdate(TopologyUpdateData),
    
    /// State proof request data
    StateProofRequest(StateProofRequestData),
    
    /// State proof response data
    StateProofResponse(StateProofResponseData),
    
    /// Data availability request data
    DataAvailabilityRequest(DataAvailabilityRequestData),
    
    /// Data availability response data
    DataAvailabilityResponse(DataAvailabilityResponseData),
    
    /// TEE attestation data
    TEEAttestation(TEEAttestationData),
    
    /// Single transaction
    Transaction(TransactionResponseData),
    
    /// Single block
    Block(BlockResponseData),
    
    /// Single object
    Object(ObjectResponseData),
    
    /// Custom data
    Custom(Vec<u8>),
}

impl fmt::Debug for MessagePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessagePayload::Empty => write!(f, "Empty"),
            MessagePayload::Handshake(_) => write!(f, "Handshake"),
            MessagePayload::Error(_) => write!(f, "Error"),
            MessagePayload::BlockRequest(_) => write!(f, "BlockRequest"),
            MessagePayload::BlockResponse(_) => write!(f, "BlockResponse"),
            MessagePayload::BlocksRequest(_) => write!(f, "BlocksRequest"),
            MessagePayload::BlocksResponse(_) => write!(f, "BlocksResponse"),
            MessagePayload::TransactionRequest(_) => write!(f, "TransactionRequest"),
            MessagePayload::TransactionResponse(_) => write!(f, "TransactionResponse"),
            MessagePayload::ObjectRequest(_) => write!(f, "ObjectRequest"),
            MessagePayload::ObjectResponse(_) => write!(f, "ObjectResponse"),
            MessagePayload::ChainInfo(_) => write!(f, "ChainInfo"),
            MessagePayload::Peers(_) => write!(f, "Peers"),
            MessagePayload::SyncStatus(_) => write!(f, "SyncStatus"),
            MessagePayload::ValidatorSet(_) => write!(f, "ValidatorSet"),
            MessagePayload::ValidationResult(_) => write!(f, "ValidationResult"),
            MessagePayload::FinalityProof(_) => write!(f, "FinalityProof"),
            MessagePayload::UncorruptedChain(_) => write!(f, "UncorruptedChain"),
            MessagePayload::SuperpositionedStatesRequest(_) => write!(f, "SuperpositionedStatesRequest"),
            MessagePayload::SuperpositionedStatesResponse(_) => write!(f, "SuperpositionedStatesResponse"),
            MessagePayload::SecurityLevelConfirmation(_) => write!(f, "SecurityLevelConfirmation"),
            MessagePayload::BLSSignatureAggregate(_) => write!(f, "BLSSignatureAggregate"),
            MessagePayload::TopologyDiscovery(_) => write!(f, "TopologyDiscovery"),
            MessagePayload::TopologyUpdate(_) => write!(f, "TopologyUpdate"),
            MessagePayload::StateProofRequest(_) => write!(f, "StateProofRequest"),
            MessagePayload::StateProofResponse(_) => write!(f, "StateProofResponse"),
            MessagePayload::DataAvailabilityRequest(_) => write!(f, "DataAvailabilityRequest"),
            MessagePayload::DataAvailabilityResponse(_) => write!(f, "DataAvailabilityResponse"),
            MessagePayload::TEEAttestation(_) => write!(f, "TEEAttestation"),
            MessagePayload::Transaction(_) => write!(f, "Transaction"),
            MessagePayload::Block(_) => write!(f, "Block"),
            MessagePayload::Object(_) => write!(f, "Object"),
            MessagePayload::Custom(_) => write!(f, "Custom"),
        }
    }
}

/// Handshake data for connection establishment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeData {
    /// Protocol version
    pub version: ProtocolVersion,
    
    /// Node ID
    pub node_id: Vec<u8>,
    
    /// Node address
    pub address: String,
    
    /// Node capabilities
    pub capabilities: Vec<String>,
    
    /// Whether the node is a validator
    pub is_validator: bool,
    
    /// User agent string
    pub user_agent: String,
    
    /// Current height
    pub height: u64,
    
    /// Current uncorrupted chain ID
    pub chain_id: Vec<u8>,
    
    /// Node region
    pub region: String,
}

/// Error data for error messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorData {
    /// Error code
    pub code: u32,
    
    /// Error message
    pub message: String,
    
    /// Related request ID
    pub request_id: u64,
}

/// Block request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequestData {
    /// Block hash (if requesting by hash)
    pub hash: Option<Vec<u8>>,
    
    /// Block height (if requesting by height)
    pub height: Option<u64>,
    
    /// Include full transactions
    pub include_transactions: bool,
}

/// Block response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponseData {
    /// The requested block
    pub block: Option<Block>,
    
    /// Error message if the block wasn't found
    pub error: Option<String>,
}

/// Blocks request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocksRequestData {
    /// Start height
    pub start_height: u64,
    
    /// End height
    pub end_height: u64,
    
    /// Maximum number of blocks to return
    pub max_blocks: u32,
    
    /// Include full transactions
    pub include_transactions: bool,
}

/// Blocks response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocksResponseData {
    /// The requested blocks
    pub blocks: Vec<Block>,
    
    /// Whether there are more blocks available
    pub has_more: bool,
    
    /// Error message if the blocks weren't found
    pub error: Option<String>,
}

/// Transaction request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequestData {
    /// Transaction hash
    pub hash: Vec<u8>,
}

/// Transaction response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponseData {
    /// The requested transaction
    pub transaction: Option<Transaction>,
    
    /// Error message if the transaction wasn't found
    pub error: Option<String>,
}

/// Object request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectRequestData {
    /// Object ID
    pub id: ObjectID,
    
    /// Request state at a specific block height (optional)
    pub at_height: Option<u64>,
}

/// Object response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectResponseData {
    /// The requested object
    pub object: Option<Object>,
    
    /// Error message if the object wasn't found
    pub error: Option<String>,
}

/// Chain info data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfoData {
    /// Current height
    pub height: u64,
    
    /// Latest block hash
    pub latest_hash: Vec<u8>,
    
    /// Latest block timestamp
    pub latest_timestamp: u64,
    
    /// Latest finalized block height
    pub finalized_height: u64,
    
    /// Latest finalized block hash
    pub finalized_hash: Vec<u8>,
    
    /// Latest uncorrupted block height
    pub uncorrupted_height: u64,
    
    /// Latest uncorrupted block hash
    pub uncorrupted_hash: Vec<u8>,
    
    /// Number of transactions in the chain
    pub transaction_count: u64,
    
    /// Validator count
    pub validator_count: u32,
    
    /// Genesis hash
    pub genesis_hash: Vec<u8>,
    
    /// Chain ID
    pub chain_id: Vec<u8>,
}

/// Peer address data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAddressData {
    /// Peer ID
    pub id: Vec<u8>,
    
    /// Peer address
    pub address: String,
    
    /// Peer port
    pub port: u16,
    
    /// Whether the peer is a validator
    pub is_validator: bool,
    
    /// Peer region
    pub region: String,
}

/// Peers data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersData {
    /// Peer addresses
    pub peers: Vec<PeerAddressData>,
}

/// Sync status data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatusData {
    /// Current height
    pub current_height: u64,
    
    /// Target height
    pub target_height: u64,
    
    /// Sync state
    pub state: String,
    
    /// Estimated time remaining (seconds)
    pub estimated_time_remaining: Option<u64>,
    
    /// Sync speed (blocks per second)
    pub blocks_per_second: f64,
}

/// Validator data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorData {
    /// Validator ID
    pub id: Vec<u8>,
    
    /// Validator address
    pub address: String,
    
    /// Stake amount
    pub stake: u64,
    
    /// Whether the validator is active
    pub active: bool,
    
    /// Validator public key
    pub public_key: Vec<u8>,
    
    /// Validator metadata
    pub metadata: Option<Vec<u8>>,
}

/// Validator set data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetData {
    /// Validators
    pub validators: Vec<ValidatorData>,
    
    /// Total stake
    pub total_stake: u64,
    
    /// Active validator count
    pub active_count: u32,
}

/// Validation result data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResultData {
    /// Transaction hash
    pub tx_hash: Vec<u8>,
    
    /// Validation status (success/failure)
    pub success: bool,
    
    /// Error message if validation failed
    pub error: Option<String>,
    
    /// Validator ID
    pub validator_id: Vec<u8>,
    
    /// Validator signature
    pub signature: Vec<u8>,
    
    /// TEE attestation if available
    pub tee_attestation: Option<Vec<u8>>,
    
    /// Timestamp
    pub timestamp: u64,
}

/// Finality proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProofData {
    /// Block hash
    pub block_hash: Vec<u8>,
    
    /// Block height
    pub height: u64,
    
    /// Timestamp when finality was achieved
    pub timestamp: u64,
    
    /// Validator signatures
    pub signatures: HashMap<Vec<u8>, Vec<u8>>, // validator_id -> signature
    
    /// Minimum confirmations required
    pub min_confirmations: usize,
    
    /// Whether the block is uncorrupted
    pub uncorrupted: bool,
    
    /// Finality proof signature
    pub proof_signature: Vec<u8>,
}

/// Superpositioned states request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperpositionedStatesRequestData {
    /// Object IDs to request
    pub object_ids: Vec<ObjectID>,
}

/// Superpositioned state data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperpositionedStateData {
    /// Object ID
    pub object_id: ObjectID,
    
    /// Superpositioned state
    pub state: SuperpositionedState<Object>,
}

/// Superpositioned states response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperpositionedStatesResponseData {
    /// Superpositioned states
    pub states: Vec<SuperpositionedStateData>,
    
    /// Error message if the states weren't found
    pub error: Option<String>,
}

/// Security level confirmation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLevelConfirmationData {
    /// Transaction hash
    pub tx_hash: Vec<u8>,
    
    /// Security level
    pub security_level: SecurityLevel,
    
    /// Validator signature
    pub signature: Vec<u8>,
    
    /// Timestamp
    pub timestamp: u64,
}

/// BLS signature aggregate data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLSSignatureAggregateData {
    /// Transaction hash
    pub tx_hash: Vec<u8>,
    
    /// Security level
    pub security_level: SecurityLevel,
    
    /// Aggregate signature
    pub aggregate_signature: Vec<u8>,
    
    /// Signers
    pub signers: Vec<Vec<u8>>,
    
    /// Timestamp
    pub timestamp: u64,
}

/// Topology discovery data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyDiscoveryData {
    /// Node region
    pub region: String,
    
    /// Latency map (peer_id -> latency in ms)
    pub latency_map: HashMap<Vec<u8>, u32>,
    
    /// Timestamp
    pub timestamp: u64,
}

/// Topology update data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyUpdateData {
    /// Region updates (region -> peer_count)
    pub region_updates: HashMap<String, u32>,
    
    /// Timestamp
    pub timestamp: u64,
}

/// State proof request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProofRequestData {
    /// Object IDs to get proofs for
    pub object_ids: Vec<ObjectID>,
}

/// State proof response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProofResponseData {
    /// Proofs for each object (object_id -> proof)
    pub proofs: HashMap<ObjectID, Vec<u8>>,
}

/// Data availability request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAvailabilityRequestData {
    /// Block hash
    pub block_hash: Vec<u8>,
    
    /// Shard indices to request
    pub shard_indices: Vec<u32>,
}

/// Data availability response data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAvailabilityResponseData {
    /// Block hash
    pub block_hash: Vec<u8>,
    
    /// Shards (index -> data)
    pub shards: HashMap<u32, Vec<u8>>,
}

/// TEE attestation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEAttestationData {
    /// Transaction hash
    pub tx_hash: Vec<u8>,
    
    /// TEE attestation
    pub attestation: Vec<u8>,
    
    /// Timestamp
    pub timestamp: u64,
}

/// Network protocol interface
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Gets the protocol version
    fn version(&self) -> ProtocolVersion;
    
    /// Handles an incoming message
    async fn handle_message(&self, message: Message, sender_addr: SocketAddr) -> Result<Option<Message>>;
    
    /// Creates a handshake message
    fn create_handshake(&self) -> Result<Message>;
    
    /// Verifies a handshake message
    fn verify_handshake(&self, handshake: &HandshakeData) -> Result<bool>;
    
    /// Gets the ping interval
    fn ping_interval(&self) -> Duration {
        Duration::from_secs(30)
    }
    
    /// Gets the ping timeout
    fn ping_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
    
    /// Gets the protocol identifier
    fn protocol_id(&self) -> &'static str {
        "aevor/1.0"
    }
}

/// Protocol handler for specific message types
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Handles an incoming message
    async fn handle_message(&self, message: Message) -> Result<Option<Message>>;
    
    /// Gets the supported protocol version
    fn protocol_version(&self) -> ProtocolVersion;
    
    /// Gets the supported message types
    fn supported_message_types(&self) -> Vec<MessageType>;
    
    /// Checks if the handler supports a specific message type
    fn supports_message_type(&self, message_type: MessageType) -> bool {
        self.supported_message_types().contains(&message_type)
    }
}
