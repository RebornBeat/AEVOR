use serde::{Deserialize, Serialize};
use std::fmt;

/// Type of transaction in the Aevor blockchain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionType {
    /// Transfer tokens between accounts
    Transfer,
    
    /// Publish a smart contract or package
    Publish,
    
    /// Call a smart contract function
    Call,
    
    /// Create a new object
    Create,
    
    /// Delete an existing object
    Delete,
    
    /// Governance transaction (protocol parameter updates, etc.)
    Governance,
    
    /// Stake tokens for validation
    Stake,
    
    /// Unstake tokens
    Unstake,
    
    /// Delegate stake to a validator
    Delegate,
    
    /// Undelegate stake from a validator
    Undelegate,
    
    /// Claim rewards
    ClaimRewards,
    
    /// Update validator parameters
    UpdateValidator,
    
    /// Vote on governance proposals
    Vote,
    
    /// Create a governance proposal
    CreateProposal,
    
    /// Execute a governance proposal
    ExecuteProposal,
    
    /// Batch multiple transactions
    Batch,
    
    /// Custom transaction type
    Custom(u16),
}

impl TransactionType {
    /// Checks if this transaction type requires a valid sender
    pub fn requires_sender(&self) -> bool {
        match self {
            TransactionType::Governance => false, // Some governance transactions might not require a sender
            _ => true,
        }
    }
    
    /// Checks if this transaction type requires a signature
    pub fn requires_signature(&self) -> bool {
        match self {
            TransactionType::Governance => false, // Some governance transactions might not require a signature
            _ => true,
        }
    }
    
    /// Checks if this transaction type can be batched
    pub fn can_be_batched(&self) -> bool {
        match self {
            TransactionType::Batch => false, // Cannot batch a batch
            TransactionType::Governance => false, // Governance transactions cannot be batched
            TransactionType::CreateProposal => false, // Proposals cannot be batched
            TransactionType::ExecuteProposal => false, // Proposals cannot be batched
            _ => true,
        }
    }
    
    /// Checks if this transaction type needs to specify a gas limit
    pub fn needs_gas_limit(&self) -> bool {
        match self {
            TransactionType::Governance => false, // Some governance transactions might not need gas
            _ => true,
        }
    }
    
    /// Gets the transaction type name as a string
    pub fn type_name(&self) -> &'static str {
        match self {
            TransactionType::Transfer => "Transfer",
            TransactionType::Publish => "Publish",
            TransactionType::Call => "Call",
            TransactionType::Create => "Create",
            TransactionType::Delete => "Delete",
            TransactionType::Governance => "Governance",
            TransactionType::Stake => "Stake",
            TransactionType::Unstake => "Unstake",
            TransactionType::Delegate => "Delegate",
            TransactionType::Undelegate => "Undelegate",
            TransactionType::ClaimRewards => "ClaimRewards",
            TransactionType::UpdateValidator => "UpdateValidator",
            TransactionType::Vote => "Vote",
            TransactionType::CreateProposal => "CreateProposal",
            TransactionType::ExecuteProposal => "ExecuteProposal",
            TransactionType::Batch => "Batch",
            TransactionType::Custom(_) => "Custom",
        }
    }
    
    /// Convert a string to a transaction type
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "transfer" => Some(TransactionType::Transfer),
            "publish" => Some(TransactionType::Publish),
            "call" => Some(TransactionType::Call),
            "create" => Some(TransactionType::Create),
            "delete" => Some(TransactionType::Delete),
            "governance" => Some(TransactionType::Governance),
            "stake" => Some(TransactionType::Stake),
            "unstake" => Some(TransactionType::Unstake),
            "delegate" => Some(TransactionType::Delegate),
            "undelegate" => Some(TransactionType::Undelegate),
            "claimrewards" => Some(TransactionType::ClaimRewards),
            "updatevalidator" => Some(TransactionType::UpdateValidator),
            "vote" => Some(TransactionType::Vote),
            "createproposal" => Some(TransactionType::CreateProposal),
            "executeproposal" => Some(TransactionType::ExecuteProposal),
            "batch" => Some(TransactionType::Batch),
            _ => {
                // Check for custom type format: "custom-X" where X is a number
                if s.starts_with("custom-") {
                    if let Ok(num) = s[7..].parse::<u16>() {
                        return Some(TransactionType::Custom(num));
                    }
                }
                None
            }
        }
    }
}

impl fmt::Display for TransactionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionType::Custom(id) => write!(f, "Custom-{}", id),
            _ => write!(f, "{}", self.type_name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transaction_type_properties() {
        // Test requires_sender
        assert!(TransactionType::Transfer.requires_sender());
        assert!(TransactionType::Call.requires_sender());
        assert!(!TransactionType::Governance.requires_sender());
        
        // Test requires_signature
        assert!(TransactionType::Transfer.requires_signature());
        assert!(TransactionType::Call.requires_signature());
        assert!(!TransactionType::Governance.requires_signature());
        
        // Test can_be_batched
        assert!(TransactionType::Transfer.can_be_batched());
        assert!(TransactionType::Call.can_be_batched());
        assert!(!TransactionType::Batch.can_be_batched());
        assert!(!TransactionType::Governance.can_be_batched());
        
        // Test needs_gas_limit
        assert!(TransactionType::Transfer.needs_gas_limit());
        assert!(TransactionType::Call.needs_gas_limit());
        assert!(!TransactionType::Governance.needs_gas_limit());
    }
    
    #[test]
    fn test_transaction_type_names() {
        assert_eq!(TransactionType::Transfer.type_name(), "Transfer");
        assert_eq!(TransactionType::Call.type_name(), "Call");
        assert_eq!(TransactionType::Custom(123).type_name(), "Custom");
    }
    
    #[test]
    fn test_transaction_type_from_str() {
        assert_eq!(TransactionType::from_str("transfer"), Some(TransactionType::Transfer));
        assert_eq!(TransactionType::from_str("Transfer"), Some(TransactionType::Transfer));
        assert_eq!(TransactionType::from_str("TRANSFER"), Some(TransactionType::Transfer));
        assert_eq!(TransactionType::from_str("call"), Some(TransactionType::Call));
        assert_eq!(TransactionType::from_str("custom-123"), Some(TransactionType::Custom(123)));
        assert_eq!(TransactionType::from_str("unknown"), None);
    }
    
    #[test]
    fn test_transaction_type_display() {
        assert_eq!(format!("{}", TransactionType::Transfer), "Transfer");
        assert_eq!(format!("{}", TransactionType::Call), "Call");
        assert_eq!(format!("{}", TransactionType::Custom(123)), "Custom-123");
    }
}
