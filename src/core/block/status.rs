use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents the status of a block in the blockchain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockStatus {
    /// Block is pending execution
    Pending,
    
    /// Block is being validated
    Validating,
    
    /// Block has been accepted by consensus
    Accepted,
    
    /// Block has been rejected by consensus
    Rejected,
    
    /// Block has been finalized (cannot be reverted)
    Finalized,
    
    /// Block has been verified as uncorrupted
    Uncorrupted,
}

impl BlockStatus {
    /// Checks if the block status is terminal (finalized or rejected)
    pub fn is_terminal(&self) -> bool {
        match self {
            BlockStatus::Finalized => true,
            BlockStatus::Rejected => true,
            BlockStatus::Uncorrupted => true,
            _ => false,
        }
    }
    
    /// Checks if the block is in a valid state
    pub fn is_valid(&self) -> bool {
        match self {
            BlockStatus::Accepted => true,
            BlockStatus::Finalized => true,
            BlockStatus::Uncorrupted => true,
            _ => false,
        }
    }
    
    /// Checks if the block execution is complete
    pub fn is_executed(&self) -> bool {
        match self {
            BlockStatus::Pending => false,
            BlockStatus::Validating => false,
            _ => true,
        }
    }
    
    /// Gets the status name as a string
    pub fn name(&self) -> &'static str {
        match self {
            BlockStatus::Pending => "Pending",
            BlockStatus::Validating => "Validating",
            BlockStatus::Accepted => "Accepted",
            BlockStatus::Rejected => "Rejected",
            BlockStatus::Finalized => "Finalized",
            BlockStatus::Uncorrupted => "Uncorrupted",
        }
    }
}

impl fmt::Display for BlockStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_block_status_properties() {
        // Test is_terminal
        assert!(!BlockStatus::Pending.is_terminal());
        assert!(!BlockStatus::Validating.is_terminal());
        assert!(!BlockStatus::Accepted.is_terminal());
        assert!(BlockStatus::Rejected.is_terminal());
        assert!(BlockStatus::Finalized.is_terminal());
        assert!(BlockStatus::Uncorrupted.is_terminal());
        
        // Test is_valid
        assert!(!BlockStatus::Pending.is_valid());
        assert!(!BlockStatus::Validating.is_valid());
        assert!(BlockStatus::Accepted.is_valid());
        assert!(!BlockStatus::Rejected.is_valid());
        assert!(BlockStatus::Finalized.is_valid());
        assert!(BlockStatus::Uncorrupted.is_valid());
        
        // Test is_executed
        assert!(!BlockStatus::Pending.is_executed());
        assert!(!BlockStatus::Validating.is_executed());
        assert!(BlockStatus::Accepted.is_executed());
        assert!(BlockStatus::Rejected.is_executed());
        assert!(BlockStatus::Finalized.is_executed());
        assert!(BlockStatus::Uncorrupted.is_executed());
    }
    
    #[test]
    fn test_block_status_name() {
        assert_eq!(BlockStatus::Pending.name(), "Pending");
        assert_eq!(BlockStatus::Validating.name(), "Validating");
        assert_eq!(BlockStatus::Accepted.name(), "Accepted");
        assert_eq!(BlockStatus::Rejected.name(), "Rejected");
        assert_eq!(BlockStatus::Finalized.name(), "Finalized");
        assert_eq!(BlockStatus::Uncorrupted.name(), "Uncorrupted");
    }
    
    #[test]
    fn test_block_status_display() {
        assert_eq!(format!("{}", BlockStatus::Pending), "Pending");
        assert_eq!(format!("{}", BlockStatus::Validating), "Validating");
        assert_eq!(format!("{}", BlockStatus::Accepted), "Accepted");
        assert_eq!(format!("{}", BlockStatus::Rejected), "Rejected");
        assert_eq!(format!("{}", BlockStatus::Finalized), "Finalized");
        assert_eq!(format!("{}", BlockStatus::Uncorrupted), "Uncorrupted");
    }
}
