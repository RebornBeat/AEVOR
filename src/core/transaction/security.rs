use serde::{Deserialize, Serialize};
use std::fmt;

/// Security level for a transaction in the Aevor blockchain
///
/// The Security Level Accelerator provides tiered validation with
/// progressive security guarantees from milliseconds to sub-second timeframes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Minimal security level (20-50ms)
    /// - Single validator with TEE attestation
    /// - Provides subjective certainty through TEE integrity guarantees
    /// - Suitable for low-value transactions and UI feedback
    Minimal = 0,
    
    /// Basic security level (100-200ms)
    /// - Confirmations from 10-20% of validators
    /// - Selected through topology-aware validation solicitation
    /// - Balances speed and robustness against limited collusion
    Basic = 1,
    
    /// Strong security level (500-800ms)
    /// - Confirmations from >1/3 of validators
    /// - Provides Byzantine fault tolerance against limited attacks
    /// - Uses BLS threshold signatures for efficient validation proof
    Strong = 2,
    
    /// Full security level (<1s)
    /// - Traditional BFT guarantee with >2/3 validator confirmations
    /// - Integrated with the macro-DAG for global consensus
    /// - Suitable for high-value transactions and settlement
    Full = 3,
}

impl SecurityLevel {
    /// Gets the security level value as a u8
    pub fn value(&self) -> u8 {
        *self as u8
    }
    
    /// Creates a security level from a u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(SecurityLevel::Minimal),
            1 => Some(SecurityLevel::Basic),
            2 => Some(SecurityLevel::Strong),
            3 => Some(SecurityLevel::Full),
            _ => None,
        }
    }
    
    /// Gets the security level name
    pub fn name(&self) -> &'static str {
        match self {
            SecurityLevel::Minimal => "Minimal",
            SecurityLevel::Basic => "Basic",
            SecurityLevel::Strong => "Strong",
            SecurityLevel::Full => "Full",
        }
    }
    
    /// Gets the typical latency range for this security level
    pub fn latency_range(&self) -> (u64, u64) {
        match self {
            SecurityLevel::Minimal => (20, 50),   // 20-50ms
            SecurityLevel::Basic => (100, 200),   // 100-200ms
            SecurityLevel::Strong => (500, 800),  // 500-800ms
            SecurityLevel::Full => (800, 1000),   // <1s (800-1000ms)
        }
    }
    
    /// Gets the percentage of validators typically required for this security level
    pub fn validator_percentage(&self) -> (u8, u8) {
        match self {
            SecurityLevel::Minimal => (1, 1),      // Single validator (1%)
            SecurityLevel::Basic => (10, 20),      // 10-20% of validators
            SecurityLevel::Strong => (34, 50),     // >1/3 of validators (34-50%)
            SecurityLevel::Full => (67, 100),      // >2/3 of validators (67-100%)
        }
    }
    
    /// Gets the next security level (if any)
    pub fn next(&self) -> Option<Self> {
        match self {
            SecurityLevel::Minimal => Some(SecurityLevel::Basic),
            SecurityLevel::Basic => Some(SecurityLevel::Strong),
            SecurityLevel::Strong => Some(SecurityLevel::Full),
            SecurityLevel::Full => None,
        }
    }
    
    /// Gets the previous security level (if any)
    pub fn prev(&self) -> Option<Self> {
        match self {
            SecurityLevel::Minimal => None,
            SecurityLevel::Basic => Some(SecurityLevel::Minimal),
            SecurityLevel::Strong => Some(SecurityLevel::Basic),
            SecurityLevel::Full => Some(SecurityLevel::Strong),
        }
    }
    
    /// Checks if this security level is sufficient for the given value
    pub fn is_sufficient_for_value(&self, value: u64) -> bool {
        // Define value thresholds for each security level
        const MINIMAL_THRESHOLD: u64 = 100;         // Up to 100 tokens
        const BASIC_THRESHOLD: u64 = 10_000;        // Up to 10,000 tokens
        const STRONG_THRESHOLD: u64 = 1_000_000;    // Up to 1,000,000 tokens
        
        match self {
            SecurityLevel::Minimal => value <= MINIMAL_THRESHOLD,
            SecurityLevel::Basic => value <= BASIC_THRESHOLD,
            SecurityLevel::Strong => value <= STRONG_THRESHOLD,
            SecurityLevel::Full => true, // Full security is sufficient for any value
        }
    }
    
    /// Suggests a security level based on transaction value
    pub fn suggest_for_value(value: u64) -> Self {
        // Define value thresholds for each security level
        const MINIMAL_THRESHOLD: u64 = 100;         // Up to 100 tokens
        const BASIC_THRESHOLD: u64 = 10_000;        // Up to 10,000 tokens
        const STRONG_THRESHOLD: u64 = 1_000_000;    // Up to 1,000,000 tokens
        
        if value <= MINIMAL_THRESHOLD {
            SecurityLevel::Minimal
        } else if value <= BASIC_THRESHOLD {
            SecurityLevel::Basic
        } else if value <= STRONG_THRESHOLD {
            SecurityLevel::Strong
        } else {
            SecurityLevel::Full
        }
    }
    
    /// Returns the minimum number of validators needed for this security level
    /// based on the total validator count
    pub fn min_validators(&self, total_validators: usize) -> usize {
        let (min_pct, _) = self.validator_percentage();
        
        match self {
            SecurityLevel::Minimal => 1, // Always need at least one validator
            _ => {
                // Calculate based on percentage
                let min_count = (total_validators * min_pct as usize) / 100;
                
                // Ensure at least one validator
                std::cmp::max(1, min_count)
            }
        }
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Minimal
    }
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Trait for types that have security levels
pub trait HasSecurityLevel {
    /// Gets the security level
    fn security_level(&self) -> SecurityLevel;
    
    /// Sets the security level
    fn set_security_level(&mut self, level: SecurityLevel);
    
    /// Upgrades to the next security level if possible
    fn upgrade_security_level(&mut self) -> bool {
        if let Some(next_level) = self.security_level().next() {
            self.set_security_level(next_level);
            true
        } else {
            false
        }
    }
    
    /// Checks if the security level is at least the specified level
    fn has_security_level_at_least(&self, level: SecurityLevel) -> bool {
        self.security_level() >= level
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_level_from_u8() {
        assert_eq!(SecurityLevel::from_u8(0), Some(SecurityLevel::Minimal));
        assert_eq!(SecurityLevel::from_u8(1), Some(SecurityLevel::Basic));
        assert_eq!(SecurityLevel::from_u8(2), Some(SecurityLevel::Strong));
        assert_eq!(SecurityLevel::from_u8(3), Some(SecurityLevel::Full));
        assert_eq!(SecurityLevel::from_u8(4), None);
    }
    
    #[test]
    fn test_security_level_value() {
        assert_eq!(SecurityLevel::Minimal.value(), 0);
        assert_eq!(SecurityLevel::Basic.value(), 1);
        assert_eq!(SecurityLevel::Strong.value(), 2);
        assert_eq!(SecurityLevel::Full.value(), 3);
    }
    
    #[test]
    fn test_security_level_name() {
        assert_eq!(SecurityLevel::Minimal.name(), "Minimal");
        assert_eq!(SecurityLevel::Basic.name(), "Basic");
        assert_eq!(SecurityLevel::Strong.name(), "Strong");
        assert_eq!(SecurityLevel::Full.name(), "Full");
    }
    
    #[test]
    fn test_security_level_next() {
        assert_eq!(SecurityLevel::Minimal.next(), Some(SecurityLevel::Basic));
        assert_eq!(SecurityLevel::Basic.next(), Some(SecurityLevel::Strong));
        assert_eq!(SecurityLevel::Strong.next(), Some(SecurityLevel::Full));
        assert_eq!(SecurityLevel::Full.next(), None);
    }
    
    #[test]
    fn test_security_level_prev() {
        assert_eq!(SecurityLevel::Minimal.prev(), None);
        assert_eq!(SecurityLevel::Basic.prev(), Some(SecurityLevel::Minimal));
        assert_eq!(SecurityLevel::Strong.prev(), Some(SecurityLevel::Basic));
        assert_eq!(SecurityLevel::Full.prev(), Some(SecurityLevel::Strong));
    }
    
    #[test]
    fn test_security_level_latency_range() {
        assert_eq!(SecurityLevel::Minimal.latency_range(), (20, 50));
        assert_eq!(SecurityLevel::Basic.latency_range(), (100, 200));
        assert_eq!(SecurityLevel::Strong.latency_range(), (500, 800));
        assert_eq!(SecurityLevel::Full.latency_range(), (800, 1000));
    }
    
    #[test]
    fn test_security_level_validator_percentage() {
        assert_eq!(SecurityLevel::Minimal.validator_percentage(), (1, 1));
        assert_eq!(SecurityLevel::Basic.validator_percentage(), (10, 20));
        assert_eq!(SecurityLevel::Strong.validator_percentage(), (34, 50));
        assert_eq!(SecurityLevel::Full.validator_percentage(), (67, 100));
    }
    
    #[test]
    fn test_security_level_is_sufficient_for_value() {
        assert!(SecurityLevel::Minimal.is_sufficient_for_value(50));
        assert!(!SecurityLevel::Minimal.is_sufficient_for_value(500));
        
        assert!(SecurityLevel::Basic.is_sufficient_for_value(5000));
        assert!(!SecurityLevel::Basic.is_sufficient_for_value(50000));
        
        assert!(SecurityLevel::Strong.is_sufficient_for_value(500000));
        assert!(!SecurityLevel::Strong.is_sufficient_for_value(5000000));
        
        assert!(SecurityLevel::Full.is_sufficient_for_value(5000000));
    }
    
    #[test]
    fn test_security_level_suggest_for_value() {
        assert_eq!(SecurityLevel::suggest_for_value(50), SecurityLevel::Minimal);
        assert_eq!(SecurityLevel::suggest_for_value(500), SecurityLevel::Basic);
        assert_eq!(SecurityLevel::suggest_for_value(50000), SecurityLevel::Strong);
        assert_eq!(SecurityLevel::suggest_for_value(5000000), SecurityLevel::Full);
    }
    
    #[test]
    fn test_security_level_min_validators() {
        // Test with 100 validators
        assert_eq!(SecurityLevel::Minimal.min_validators(100), 1);
        assert_eq!(SecurityLevel::Basic.min_validators(100), 10); // 10%
        assert_eq!(SecurityLevel::Strong.min_validators(100), 34); // 34%
        assert_eq!(SecurityLevel::Full.min_validators(100), 67); // 67%
        
        // Test with 7 validators
        assert_eq!(SecurityLevel::Minimal.min_validators(7), 1);
        assert_eq!(SecurityLevel::Basic.min_validators(7), 1); // 10% of 7 rounds to 0, but we ensure at least 1
        assert_eq!(SecurityLevel::Strong.min_validators(7), 2); // 34% of 7 is 2.38, rounds to 2
        assert_eq!(SecurityLevel::Full.min_validators(7), 4); // 67% of 7 is 4.69, rounds to 4
    }
    
    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Minimal < SecurityLevel::Basic);
        assert!(SecurityLevel::Basic < SecurityLevel::Strong);
        assert!(SecurityLevel::Strong < SecurityLevel::Full);
        
        assert!(SecurityLevel::Full > SecurityLevel::Strong);
        assert!(SecurityLevel::Strong > SecurityLevel::Basic);
        assert!(SecurityLevel::Basic > SecurityLevel::Minimal);
    }
    
    // Test HasSecurityLevel trait with a simple struct
    #[derive(Debug, PartialEq)]
    struct TestSecurityItem {
        level: SecurityLevel,
    }
    
    impl HasSecurityLevel for TestSecurityItem {
        fn security_level(&self) -> SecurityLevel {
            self.level
        }
        
        fn set_security_level(&mut self, level: SecurityLevel) {
            self.level = level;
        }
    }
    
    #[test]
    fn test_has_security_level_trait() {
        let mut item = TestSecurityItem { level: SecurityLevel::Minimal };
        
        // Test initial level
        assert_eq!(item.security_level(), SecurityLevel::Minimal);
        
        // Test upgrade
        assert!(item.upgrade_security_level());
        assert_eq!(item.security_level(), SecurityLevel::Basic);
        
        // Test has_security_level_at_least
        assert!(item.has_security_level_at_least(SecurityLevel::Minimal));
        assert!(item.has_security_level_at_least(SecurityLevel::Basic));
        assert!(!item.has_security_level_at_least(SecurityLevel::Strong));
        
        // Test set_security_level
        item.set_security_level(SecurityLevel::Full);
        assert_eq!(item.security_level(), SecurityLevel::Full);
        
        // Test upgrade at maximum level
        assert!(!item.upgrade_security_level());
        assert_eq!(item.security_level(), SecurityLevel::Full);
    }
}
