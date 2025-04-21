use serde::{Deserialize, Serialize};
use std::fmt;

use crate::core::object::DependencyType;

/// Represents a dependency between transactions
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionDependency {
    /// Hash of the transaction this depends on
    pub tx_hash: Vec<u8>,
    
    /// Type of dependency
    pub dependency_type: DependencyType,
    
    /// Priority of this dependency (higher = more important)
    pub priority: u8,
    
    /// Whether this dependency is required for execution
    pub required: bool,
}

impl TransactionDependency {
    /// Creates a new transaction dependency
    pub fn new(tx_hash: Vec<u8>, dependency_type: DependencyType) -> Self {
        Self {
            tx_hash,
            dependency_type,
            priority: Self::default_priority(dependency_type),
            required: Self::default_required(dependency_type),
        }
    }
    
    /// Creates a new transaction dependency with custom priority and requirement
    pub fn with_options(tx_hash: Vec<u8>, dependency_type: DependencyType, priority: u8, required: bool) -> Self {
        Self {
            tx_hash,
            dependency_type,
            priority,
            required,
        }
    }
    
    /// Gets the default priority for a dependency type
    pub fn default_priority(dependency_type: DependencyType) -> u8 {
        match dependency_type {
            DependencyType::ReadAfterWrite => 3, // Highest priority
            DependencyType::WriteAfterWrite => 2,
            DependencyType::WriteAfterRead => 1,
            DependencyType::None => 0,
        }
    }
    
    /// Gets whether a dependency type is required by default
    pub fn default_required(dependency_type: DependencyType) -> bool {
        match dependency_type {
            DependencyType::ReadAfterWrite => true,
            DependencyType::WriteAfterWrite => true,
            DependencyType::WriteAfterRead => false,
            DependencyType::None => false,
        }
    }
    
    /// Gets the transaction hash
    pub fn tx_hash(&self) -> &[u8] {
        &self.tx_hash
    }
    
    /// Gets the dependency type
    pub fn dependency_type(&self) -> DependencyType {
        self.dependency_type
    }
    
    /// Gets the priority
    pub fn priority(&self) -> u8 {
        self.priority
    }
    
    /// Checks if this dependency is required
    pub fn is_required(&self) -> bool {
        self.required
    }
    
    /// Sets the priority
    pub fn set_priority(&mut self, priority: u8) {
        self.priority = priority;
    }
    
    /// Sets whether this dependency is required
    pub fn set_required(&mut self, required: bool) {
        self.required = required;
    }
}

impl fmt::Debug for TransactionDependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransactionDependency")
            .field("tx_hash", &hex::encode(&self.tx_hash))
            .field("dependency_type", &self.dependency_type)
            .field("priority", &self.priority)
            .field("required", &self.required)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transaction_dependency_new() {
        let tx_hash = vec![1, 2, 3, 4];
        let dependency_type = DependencyType::ReadAfterWrite;
        
        let dependency = TransactionDependency::new(tx_hash.clone(), dependency_type);
        
        assert_eq!(dependency.tx_hash(), &tx_hash);
        assert_eq!(dependency.dependency_type(), dependency_type);
        assert_eq!(dependency.priority(), TransactionDependency::default_priority(dependency_type));
        assert_eq!(dependency.is_required(), TransactionDependency::default_required(dependency_type));
    }
    
    #[test]
    fn test_transaction_dependency_with_options() {
        let tx_hash = vec![1, 2, 3, 4];
        let dependency_type = DependencyType::ReadAfterWrite;
        let priority = 5;
        let required = false;
        
        let dependency = TransactionDependency::with_options(tx_hash.clone(), dependency_type, priority, required);
        
        assert_eq!(dependency.tx_hash(), &tx_hash);
        assert_eq!(dependency.dependency_type(), dependency_type);
        assert_eq!(dependency.priority(), priority);
        assert_eq!(dependency.is_required(), required);
    }
    
    #[test]
    fn test_default_priority() {
        assert_eq!(TransactionDependency::default_priority(DependencyType::ReadAfterWrite), 3);
        assert_eq!(TransactionDependency::default_priority(DependencyType::WriteAfterWrite), 2);
        assert_eq!(TransactionDependency::default_priority(DependencyType::WriteAfterRead), 1);
        assert_eq!(TransactionDependency::default_priority(DependencyType::None), 0);
    }
    
    #[test]
    fn test_default_required() {
        assert_eq!(TransactionDependency::default_required(DependencyType::ReadAfterWrite), true);
        assert_eq!(TransactionDependency::default_required(DependencyType::WriteAfterWrite), true);
        assert_eq!(TransactionDependency::default_required(DependencyType::WriteAfterRead), false);
        assert_eq!(TransactionDependency::default_required(DependencyType::None), false);
    }
    
    #[test]
    fn test_setters() {
        let tx_hash = vec![1, 2, 3, 4];
        let dependency_type = DependencyType::ReadAfterWrite;
        
        let mut dependency = TransactionDependency::new(tx_hash, dependency_type);
        
        // Test setting priority
        let new_priority = 10;
        dependency.set_priority(new_priority);
        assert_eq!(dependency.priority(), new_priority);
        
        // Test setting required flag
        let new_required = !dependency.is_required();
        dependency.set_required(new_required);
        assert_eq!(dependency.is_required(), new_required);
    }
}
