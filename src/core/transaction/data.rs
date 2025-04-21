use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::object::ObjectID;
use crate::error::{AevorError, Result};
use super::types::TransactionType;

/// Data for a token transfer transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferData {
    /// Recipient address
    pub recipient: Vec<u8>,
    
    /// Transfer amount
    pub amount: u64,
}

/// Data for a contract publication transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishData {
    /// Contract name
    pub name: String,
    
    /// Contract bytecode
    pub bytecode: Vec<u8>,
    
    /// Contract initialization arguments (if any)
    pub init_args: Vec<Vec<u8>>,
}

/// Data for a contract call transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallData {
    /// Contract address or object ID
    pub contract: ObjectID,
    
    /// Function name
    pub function: String,
    
    /// Function arguments
    pub args: Vec<Vec<u8>>,
    
    /// Allow state changes
    pub state_changes: bool,
}

/// Data for an object creation transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateData {
    /// Object type ID
    pub object_type: u16,
    
    /// Initial data for the object
    pub initial_data: Vec<u8>,
    
    /// Object initial owner (if not the transaction sender)
    pub owner: Option<Vec<u8>>,
    
    /// Object metadata
    pub metadata: Vec<(String, Vec<u8>)>,
}

/// Data for an object deletion transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteData {
    /// Object ID to delete
    pub object_id: ObjectID,
}

/// Data for a governance transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceData {
    /// Governance action code
    pub action: u32,
    
    /// Governance parameters
    pub params: Vec<u8>,
}

/// Data for a staking transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeData {
    /// Staking amount
    pub amount: u64,
    
    /// Validator ID (if not the transaction sender)
    pub validator: Option<Vec<u8>>,
}

/// Data for an unstaking transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnstakeData {
    /// Unstaking amount
    pub amount: u64,
}

/// Data for a delegation transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateData {
    /// Delegation amount
    pub amount: u64,
    
    /// Validator to delegate to
    pub validator: Vec<u8>,
}

/// Data for an undelegation transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndelegateData {
    /// Undelegation amount
    pub amount: u64,
    
    /// Validator to undelegate from
    pub validator: Vec<u8>,
}

/// Data for a reward claim transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRewardsData {
    /// Validator to claim from (or None for all validators)
    pub validator: Option<Vec<u8>>,
}

/// Data for a validator update transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateValidatorData {
    /// Commission rate (0-10000 representing 0%-100%)
    pub commission_rate: Option<u16>,
    
    /// Validator metadata
    pub metadata: Option<Vec<u8>>,
    
    /// Validator configuration
    pub config: Option<Vec<u8>>,
}

/// Data for a voting transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteData {
    /// Proposal ID
    pub proposal_id: u64,
    
    /// Vote (true = yes, false = no)
    pub vote: bool,
    
    /// Optional vote weight (if different from account's full voting power)
    pub weight: Option<u64>,
}

/// Data for a proposal creation transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateProposalData {
    /// Proposal title
    pub title: String,
    
    /// Proposal description
    pub description: String,
    
    /// Proposal type
    pub proposal_type: u8,
    
    /// Proposal data (specific to the proposal type)
    pub data: Vec<u8>,
    
    /// Voting period in blocks
    pub voting_period: u64,
}

/// Data for a proposal execution transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteProposalData {
    /// Proposal ID
    pub proposal_id: u64,
}

/// Data for a batch transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchData {
    /// Sub-transactions in the batch
    pub transactions: Vec<Vec<u8>>,
}

/// Data for a custom transaction
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomData {
    /// Custom transaction type ID
    pub type_id: u16,
    
    /// Custom data
    pub data: Vec<u8>,
}

/// Transaction data variants for different transaction types
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionData {
    /// Transfer tokens
    Transfer(TransferData),
    
    /// Publish a contract
    Publish(PublishData),
    
    /// Call a contract
    Call(CallData),
    
    /// Create an object
    Create(CreateData),
    
    /// Delete an object
    Delete(DeleteData),
    
    /// Governance action
    Governance(GovernanceData),
    
    /// Stake tokens
    Stake(StakeData),
    
    /// Unstake tokens
    Unstake(UnstakeData),
    
    /// Delegate stake
    Delegate(DelegateData),
    
    /// Undelegate stake
    Undelegate(UndelegateData),
    
    /// Claim rewards
    ClaimRewards(ClaimRewardsData),
    
    /// Update validator
    UpdateValidator(UpdateValidatorData),
    
    /// Vote on a proposal
    Vote(VoteData),
    
    /// Create a proposal
    CreateProposal(CreateProposalData),
    
    /// Execute a proposal
    ExecuteProposal(ExecuteProposalData),
    
    /// Batch of transactions
    Batch(BatchData),
    
    /// Custom transaction
    Custom(CustomData),
}

impl TransactionData {
    /// Get the transaction type for this data
    pub fn transaction_type(&self) -> TransactionType {
        match self {
            TransactionData::Transfer(_) => TransactionType::Transfer,
            TransactionData::Publish(_) => TransactionType::Publish,
            TransactionData::Call(_) => TransactionType::Call,
            TransactionData::Create(_) => TransactionType::Create,
            TransactionData::Delete(_) => TransactionType::Delete,
            TransactionData::Governance(_) => TransactionType::Governance,
            TransactionData::Stake(_) => TransactionType::Stake,
            TransactionData::Unstake(_) => TransactionType::Unstake,
            TransactionData::Delegate(_) => TransactionType::Delegate,
            TransactionData::Undelegate(_) => TransactionType::Undelegate,
            TransactionData::ClaimRewards(_) => TransactionType::ClaimRewards,
            TransactionData::UpdateValidator(_) => TransactionType::UpdateValidator,
            TransactionData::Vote(_) => TransactionType::Vote,
            TransactionData::CreateProposal(_) => TransactionType::CreateProposal,
            TransactionData::ExecuteProposal(_) => TransactionType::ExecuteProposal,
            TransactionData::Batch(_) => TransactionType::Batch,
            TransactionData::Custom(data) => TransactionType::Custom(data.type_id),
        }
    }
    
    /// Validate the basic properties of this transaction data
    pub fn validate_basic(&self) -> Result<()> {
        match self {
            TransactionData::Transfer(data) => {
                if data.recipient.is_empty() {
                    return Err(AevorError::validation("Recipient address is empty"));
                }
                if data.amount == 0 {
                    return Err(AevorError::validation("Transfer amount is zero"));
                }
            },
            TransactionData::Publish(data) => {
                if data.name.is_empty() {
                    return Err(AevorError::validation("Contract name is empty"));
                }
                if data.bytecode.is_empty() {
                    return Err(AevorError::validation("Contract bytecode is empty"));
                }
            },
            TransactionData::Call(data) => {
                if data.contract.0.is_empty() {
                    return Err(AevorError::validation("Contract address is empty"));
                }
                if data.function.is_empty() {
                    return Err(AevorError::validation("Function name is empty"));
                }
            },
            TransactionData::Create(data) => {
                if data.owner.as_ref().map_or(false, |o| o.is_empty()) {
                    return Err(AevorError::validation("Owner address is empty"));
                }
            },
            TransactionData::Delete(data) => {
                if data.object_id.0.is_empty() {
                    return Err(AevorError::validation("Object ID is empty"));
                }
            },
            TransactionData::Governance(data) => {
                if data.params.is_empty() {
                    return Err(AevorError::validation("Governance parameters are empty"));
                }
            },
            TransactionData::Stake(data) => {
                if data.amount == 0 {
                    return Err(AevorError::validation("Stake amount is zero"));
                }
                if data.validator.as_ref().map_or(false, |v| v.is_empty()) {
                    return Err(AevorError::validation("Validator address is empty"));
                }
            },
            TransactionData::Unstake(data) => {
                if data.amount == 0 {
                    return Err(AevorError::validation("Unstake amount is zero"));
                }
            },
            TransactionData::Delegate(data) => {
                if data.amount == 0 {
                    return Err(AevorError::validation("Delegation amount is zero"));
                }
                if data.validator.is_empty() {
                    return Err(AevorError::validation("Validator address is empty"));
                }
            },
            TransactionData::Undelegate(data) => {
                if data.amount == 0 {
                    return Err(AevorError::validation("Undelegation amount is zero"));
                }
                if data.validator.is_empty() {
                    return Err(AevorError::validation("Validator address is empty"));
                }
            },
            TransactionData::ClaimRewards(data) => {
                if data.validator.as_ref().map_or(false, |v| v.is_empty()) {
                    return Err(AevorError::validation("Validator address is empty"));
                }
            },
            TransactionData::UpdateValidator(data) => {
                if let Some(commission_rate) = data.commission_rate {
                    if commission_rate > 10000 {
                        return Err(AevorError::validation("Commission rate is greater than 100%"));
                    }
                }
            },
            TransactionData::Vote(data) => {
                if data.proposal_id == 0 {
                    return Err(AevorError::validation("Proposal ID is zero"));
                }
            },
            TransactionData::CreateProposal(data) => {
                if data.title.is_empty() {
                    return Err(AevorError::validation("Proposal title is empty"));
                }
                if data.voting_period == 0 {
                    return Err(AevorError::validation("Voting period is zero"));
                }
            },
            TransactionData::ExecuteProposal(data) => {
                if data.proposal_id == 0 {
                    return Err(AevorError::validation("Proposal ID is zero"));
                }
            },
            TransactionData::Batch(data) => {
                if data.transactions.is_empty() {
                    return Err(AevorError::validation("Batch contains no transactions"));
                }
                if data.transactions.len() > 100 {
                    return Err(AevorError::validation("Batch contains too many transactions"));
                }
                for tx in &data.transactions {
                    if tx.is_empty() {
                        return Err(AevorError::validation("Batch contains an empty transaction"));
                    }
                }
            },
            TransactionData::Custom(data) => {
                if data.data.is_empty() {
                    return Err(AevorError::validation("Custom data is empty"));
                }
            },
        }
        
        Ok(())
    }
    
    /// Convert the transaction data to bytes for hashing
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_else(|_| Vec::new())
    }
}

impl fmt::Debug for TransactionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionData::Transfer(data) => f.debug_struct("TransferData")
                .field("recipient", &hex::encode(&data.recipient))
                .field("amount", &data.amount)
                .finish(),
            TransactionData::Publish(data) => f.debug_struct("PublishData")
                .field("name", &data.name)
                .field("bytecode_size", &data.bytecode.len())
                .field("init_args", &data.init_args.len())
                .finish(),
            TransactionData::Call(data) => f.debug_struct("CallData")
                .field("contract", &hex::encode(&data.contract.0))
                .field("function", &data.function)
                .field("args", &data.args.len())
                .field("state_changes", &data.state_changes)
                .finish(),
            TransactionData::Create(data) => f.debug_struct("CreateData")
                .field("object_type", &data.object_type)
                .field("initial_data_size", &data.initial_data.len())
                .field("owner", &data.owner.as_ref().map(hex::encode))
                .field("metadata", &data.metadata.len())
                .finish(),
            TransactionData::Delete(data) => f.debug_struct("DeleteData")
                .field("object_id", &hex::encode(&data.object_id.0))
                .finish(),
            TransactionData::Governance(data) => f.debug_struct("GovernanceData")
                .field("action", &data.action)
                .field("params_size", &data.params.len())
                .finish(),
            TransactionData::Stake(data) => f.debug_struct("StakeData")
                .field("amount", &data.amount)
                .field("validator", &data.validator.as_ref().map(hex::encode))
                .finish(),
            TransactionData::Unstake(data) => f.debug_struct("UnstakeData")
                .field("amount", &data.amount)
                .finish(),
            TransactionData::Delegate(data) => f.debug_struct("DelegateData")
                .field("amount", &data.amount)
                .field("validator", &hex::encode(&data.validator))
                .finish(),
            TransactionData::Undelegate(data) => f.debug_struct("UndelegateData")
                .field("amount", &data.amount)
                .field("validator", &hex::encode(&data.validator))
                .finish(),
            TransactionData::ClaimRewards(data) => f.debug_struct("ClaimRewardsData")
                .field("validator", &data.validator.as_ref().map(hex::encode))
                .finish(),
            TransactionData::UpdateValidator(data) => f.debug_struct("UpdateValidatorData")
                .field("commission_rate", &data.commission_rate)
                .field("metadata", &data.metadata.as_ref().map(|m| m.len()))
                .field("config", &data.config.as_ref().map(|c| c.len()))
                .finish(),
            TransactionData::Vote(data) => f.debug_struct("VoteData")
                .field("proposal_id", &data.proposal_id)
                .field("vote", &data.vote)
                .field("weight", &data.weight)
                .finish(),
            TransactionData::CreateProposal(data) => f.debug_struct("CreateProposalData")
                .field("title", &data.title)
                .field("description", &format!("{}...", &data.description.chars().take(20).collect::<String>()))
                .field("proposal_type", &data.proposal_type)
                .field("data_size", &data.data.len())
                .field("voting_period", &data.voting_period)
                .finish(),
            TransactionData::ExecuteProposal(data) => f.debug_struct("ExecuteProposalData")
                .field("proposal_id", &data.proposal_id)
                .finish(),
            TransactionData::Batch(data) => f.debug_struct("BatchData")
                .field("transaction_count", &data.transactions.len())
                .finish(),
            TransactionData::Custom(data) => f.debug_struct("CustomData")
                .field("type_id", &data.type_id)
                .field("data_size", &data.data.len())
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transaction_data_transaction_type() {
        // Test that each transaction data variant returns the correct transaction type
        assert_eq!(TransactionData::Transfer(TransferData { recipient: vec![1], amount: 1 }).transaction_type(), TransactionType::Transfer);
        assert_eq!(TransactionData::Publish(PublishData { name: "test".to_string(), bytecode: vec![1], init_args: vec![] }).transaction_type(), TransactionType::Publish);
        assert_eq!(TransactionData::Call(CallData { contract: ObjectID(vec![1]), function: "test".to_string(), args: vec![], state_changes: true }).transaction_type(), TransactionType::Call);
        assert_eq!(TransactionData::Create(CreateData { object_type: 1, initial_data: vec![1], owner: None, metadata: vec![] }).transaction_type(), TransactionType::Create);
        assert_eq!(TransactionData::Delete(DeleteData { object_id: ObjectID(vec![1]) }).transaction_type(), TransactionType::Delete);
        assert_eq!(TransactionData::Governance(GovernanceData { action: 1, params: vec![1] }).transaction_type(), TransactionType::Governance);
        
        // Custom transaction type
        let custom_type_id = 123;
        assert_eq!(
            TransactionData::Custom(CustomData { type_id: custom_type_id, data: vec![1] }).transaction_type(),
            TransactionType::Custom(custom_type_id)
        );
    }
    
    #[test]
    fn test_transaction_data_validation() {
        // Test valid data
        let transfer_data = TransactionData::Transfer(TransferData { recipient: vec![1], amount: 1 });
        assert!(transfer_data.validate_basic().is_ok());
        
        // Test invalid data
        let invalid_transfer_data = TransactionData::Transfer(TransferData { recipient: vec![1], amount: 0 });
        assert!(invalid_transfer_data.validate_basic().is_err());
        
        let invalid_publish_data = TransactionData::Publish(PublishData { name: "".to_string(), bytecode: vec![1], init_args: vec![] });
        assert!(invalid_publish_data.validate_basic().is_err());
        
        let invalid_call_data = TransactionData::Call(CallData { contract: ObjectID(vec![]), function: "test".to_string(), args: vec![], state_changes: true });
        assert!(invalid_call_data.validate_basic().is_err());
    }
    
    #[test]
    fn test_transaction_data_to_bytes() {
        // Test that to_bytes() returns non-empty bytes for valid data
        let transfer_data = TransactionData::Transfer(TransferData { recipient: vec![1], amount: 1 });
        let bytes = transfer_data.to_bytes();
        assert!(!bytes.is_empty());
        
        // Test that different data returns different bytes
        let transfer_data2 = TransactionData::Transfer(TransferData { recipient: vec![2], amount: 2 });
        let bytes2 = transfer_data2.to_bytes();
        assert_ne!(bytes, bytes2);
    }
}
