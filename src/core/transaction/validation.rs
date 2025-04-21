use serde::{Deserialize, Serialize};
use std::fmt;
use std::collections::HashMap;

use super::security::SecurityLevel;

/// Status of a transaction validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidationStatus {
    /// Transaction is pending validation
    Pending,
    
    /// Transaction is being validated
    Validating,
    
    /// Transaction validation succeeded
    Valid,
    
    /// Transaction validation failed
    Invalid,
    
    /// Transaction validation timed out
    Timeout,
    
    /// Transaction validation was skipped
    Skipped,
}

impl ValidationStatus {
    /// Checks if the validation status is final (not pending or validating)
    pub fn is_final(&self) -> bool {
        match self {
            ValidationStatus::Pending => false,
            ValidationStatus::Validating => false,
            ValidationStatus::Valid => true,
            ValidationStatus::Invalid => true,
            ValidationStatus::Timeout => true,
            ValidationStatus::Skipped => true,
        }
    }
    
    /// Checks if the validation is successful
    pub fn is_valid(&self) -> bool {
        match self {
            ValidationStatus::Valid => true,
            _ => false,
        }
    }
}

impl fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationStatus::Pending => write!(f, "Pending"),
            ValidationStatus::Validating => write!(f, "Validating"),
            ValidationStatus::Valid => write!(f, "Valid"),
            ValidationStatus::Invalid => write!(f, "Invalid"),
            ValidationStatus::Timeout => write!(f, "Timeout"),
            ValidationStatus::Skipped => write!(f, "Skipped"),
        }
    }
}

/// Represents the validation result for a transaction
#[derive(Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Transaction hash
    pub tx_hash: Vec<u8>,
    
    /// Validation status
    pub status: ValidationStatus,
    
    /// Validator ID
    pub validator_id: Vec<u8>,
    
    /// Validator signature
    pub signature: Vec<u8>,
    
    /// Error message (if validation failed)
    pub error: Option<String>,
    
    /// Timestamp when validation was completed
    pub timestamp: u64,
    
    /// Validation execution time in milliseconds
    pub execution_time_ms: u64,
    
    /// TEE attestation (if available)
    pub tee_attestation: Option<Vec<u8>>,
    
    /// Security level of this validation
    pub security_level: SecurityLevel,
}

impl ValidationResult {
    /// Creates a new validation result
    pub fn new(
        tx_hash: Vec<u8>,
        status: ValidationStatus,
        validator_id: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            tx_hash,
            status,
            validator_id,
            signature,
            error: None,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            execution_time_ms: 0,
            tee_attestation: None,
            security_level: SecurityLevel::Minimal,
        }
    }
    
    /// Creates a validation result with a validation error
    pub fn with_error(
        tx_hash: Vec<u8>,
        validator_id: Vec<u8>,
        signature: Vec<u8>,
        error: String,
    ) -> Self {
        Self {
            tx_hash,
            status: ValidationStatus::Invalid,
            validator_id,
            signature,
            error: Some(error),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            execution_time_ms: 0,
            tee_attestation: None,
            security_level: SecurityLevel::Minimal,
        }
    }
    
    /// Creates a validation result with TEE attestation
    pub fn with_attestation(
        tx_hash: Vec<u8>,
        status: ValidationStatus,
        validator_id: Vec<u8>,
        signature: Vec<u8>,
        tee_attestation: Vec<u8>,
    ) -> Self {
        Self {
            tx_hash,
            status,
            validator_id,
            signature,
            error: None,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            execution_time_ms: 0,
            tee_attestation: Some(tee_attestation),
            security_level: SecurityLevel::Minimal,
        }
    }
    
    /// Sets the execution time
    pub fn with_execution_time(mut self, execution_time_ms: u64) -> Self {
        self.execution_time_ms = execution_time_ms;
        self
    }
    
    /// Sets the security level
    pub fn with_security_level(mut self, security_level: SecurityLevel) -> Self {
        self.security_level = security_level;
        self
    }
    
    /// Checks if the validation result has an attestation
    pub fn has_attestation(&self) -> bool {
        self.tee_attestation.is_some()
    }
    
    /// Verifies the validation signature (placeholder for actual verification)
    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        // In a real implementation, this would actually verify the signature
        // For now, we'll just return true
        true
    }
}

impl fmt::Debug for ValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidationResult")
            .field("tx_hash", &hex::encode(&self.tx_hash))
            .field("status", &self.status)
            .field("validator_id", &hex::encode(&self.validator_id))
            .field("error", &self.error)
            .field("timestamp", &self.timestamp)
            .field("execution_time_ms", &self.execution_time_ms)
            .field("has_attestation", &self.has_attestation())
            .field("security_level", &self.security_level)
            .finish()
    }
}

/// Manager for tracking validation results
#[derive(Clone, Default)]
pub struct ValidationTracker {
    /// Validation results by transaction hash
    results: HashMap<Vec<u8>, HashMap<Vec<u8>, ValidationResult>>,
    
    /// Number of validators required for each security level
    validators_required: HashMap<SecurityLevel, usize>,
}

impl ValidationTracker {
    /// Creates a new validation tracker
    pub fn new() -> Self {
        let mut validators_required = HashMap::new();
        validators_required.insert(SecurityLevel::Minimal, 1);
        validators_required.insert(SecurityLevel::Basic, 0); // Will be set based on total validators
        validators_required.insert(SecurityLevel::Strong, 0); // Will be set based on total validators
        validators_required.insert(SecurityLevel::Full, 0); // Will be set based on total validators
        
        Self {
            results: HashMap::new(),
            validators_required,
        }
    }
    
    /// Configures the number of validators required for each security level
    pub fn configure_security_levels(&mut self, total_validators: usize) {
        self.validators_required.insert(SecurityLevel::Minimal, 1);
        self.validators_required.insert(SecurityLevel::Basic, (total_validators * 15) / 100); // 15%
        self.validators_required.insert(SecurityLevel::Strong, (total_validators * 34) / 100); // 34%
        self.validators_required.insert(SecurityLevel::Full, (total_validators * 67) / 100); // 67%
        
        // Ensure at least 1 validator for each level
        for level in &[SecurityLevel::Basic, SecurityLevel::Strong, SecurityLevel::Full] {
            if let Some(count) = self.validators_required.get_mut(level) {
                if *count == 0 {
                    *count = 1;
                }
            }
        }
    }
    
    /// Adds a validation result
    pub fn add_result(&mut self, result: ValidationResult) {
        let tx_hash = result.tx_hash.clone();
        let validator_id = result.validator_id.clone();
        
        // Get or create the validator map for this transaction
        let validator_results = self.results
            .entry(tx_hash)
            .or_insert_with(HashMap::new);
        
        // Add the result
        validator_results.insert(validator_id, result);
    }
    
    /// Gets validation results for a transaction
    pub fn get_results(&self, tx_hash: &[u8]) -> Option<&HashMap<Vec<u8>, ValidationResult>> {
        self.results.get(tx_hash)
    }
    
    /// Gets a specific validation result
    pub fn get_result(&self, tx_hash: &[u8], validator_id: &[u8]) -> Option<&ValidationResult> {
        self.results
            .get(tx_hash)
            .and_then(|validators| validators.get(validator_id))
    }
    
    /// Gets the number of validations for a transaction
    pub fn validation_count(&self, tx_hash: &[u8]) -> usize {
        self.results
            .get(tx_hash)
            .map(|validators| validators.len())
            .unwrap_or(0)
    }
    
    /// Gets the number of validations with a specific status
    pub fn validation_count_with_status(&self, tx_hash: &[u8], status: ValidationStatus) -> usize {
        self.results
            .get(tx_hash)
            .map(|validators| {
                validators
                    .values()
                    .filter(|result| result.status == status)
                    .count()
            })
            .unwrap_or(0)
    }
    
    /// Gets the current security level for a transaction
    pub fn security_level(&self, tx_hash: &[u8]) -> SecurityLevel {
        let valid_count = self.validation_count_with_status(tx_hash, ValidationStatus::Valid);
        
        if valid_count >= self.validators_required[&SecurityLevel::Full] {
            SecurityLevel::Full
        } else if valid_count >= self.validators_required[&SecurityLevel::Strong] {
            SecurityLevel::Strong
        } else if valid_count >= self.validators_required[&SecurityLevel::Basic] {
            SecurityLevel::Basic
        } else if valid_count >= self.validators_required[&SecurityLevel::Minimal] {
            SecurityLevel::Minimal
        } else {
            SecurityLevel::Minimal // Default to minimal if we don't have any validations
        }
    }
    
    /// Checks if a transaction has reached a specific security level
    pub fn has_reached_security_level(&self, tx_hash: &[u8], level: SecurityLevel) -> bool {
        let valid_count = self.validation_count_with_status(tx_hash, ValidationStatus::Valid);
        let required = self.validators_required[&level];
        
        valid_count >= required
    }
    
    /// Checks if a transaction has been validated by a specific validator
    pub fn is_validated_by(&self, tx_hash: &[u8], validator_id: &[u8]) -> bool {
        self.get_result(tx_hash, validator_id)
            .map(|result| result.status == ValidationStatus::Valid)
            .unwrap_or(false)
    }
    
    /// Gets validators that have validated a transaction
    pub fn get_validators(&self, tx_hash: &[u8]) -> Vec<Vec<u8>> {
        self.results
            .get(tx_hash)
            .map(|validators| {
                validators
                    .keys()
                    .cloned()
                    .collect()
            })
            .unwrap_or_else(Vec::new)
    }
    
    /// Gets validators that have validated a transaction with a specific status
    pub fn get_validators_with_status(&self, tx_hash: &[u8], status: ValidationStatus) -> Vec<Vec<u8>> {
        self.results
            .get(tx_hash)
            .map(|validators| {
                validators
                    .iter()
                    .filter(|(_, result)| result.status == status)
                    .map(|(validator_id, _)| validator_id.clone())
                    .collect()
            })
            .unwrap_or_else(Vec::new)
    }
    
    /// Clears validations for a transaction
    pub fn clear_transaction(&mut self, tx_hash: &[u8]) {
        self.results.remove(tx_hash);
    }
    
    /// Gets all transaction hashes being tracked
    pub fn get_transaction_hashes(&self) -> Vec<Vec<u8>> {
        self.results.keys().cloned().collect()
    }
    
    /// Gets the number of validators required for a security level
    pub fn validators_required(&self, level: SecurityLevel) -> usize {
        self.validators_required[&level]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validation_status() {
        assert!(!ValidationStatus::Pending.is_final());
        assert!(!ValidationStatus::Validating.is_final());
        assert!(ValidationStatus::Valid.is_final());
        assert!(ValidationStatus::Invalid.is_final());
        assert!(ValidationStatus::Timeout.is_final());
        assert!(ValidationStatus::Skipped.is_final());
        
        assert!(ValidationStatus::Valid.is_valid());
        assert!(!ValidationStatus::Invalid.is_valid());
        assert!(!ValidationStatus::Pending.is_valid());
    }
    
    #[test]
    fn test_validation_result() {
        let tx_hash = vec![1, 2, 3, 4];
        let validator_id = vec![5, 6, 7, 8];
        let signature = vec![9, 10, 11, 12];
        
        // Test basic validation result
        let result = ValidationResult::new(tx_hash.clone(), ValidationStatus::Valid, validator_id.clone(), signature.clone());
        assert_eq!(result.tx_hash, tx_hash);
        assert_eq!(result.status, ValidationStatus::Valid);
        assert_eq!(result.validator_id, validator_id);
        assert_eq!(result.signature, signature);
        assert!(result.error.is_none());
        assert!(!result.has_attestation());
        
        // Test with error
        let error = "Test error".to_string();
        let result = ValidationResult::with_error(tx_hash.clone(), validator_id.clone(), signature.clone(), error.clone());
        assert_eq!(result.status, ValidationStatus::Invalid);
        assert_eq!(result.error, Some(error));
        
        // Test with attestation
        let attestation = vec![13, 14, 15, 16];
        let result = ValidationResult::with_attestation(tx_hash.clone(), ValidationStatus::Valid, validator_id.clone(), signature.clone(), attestation.clone());
        assert!(result.has_attestation());
        assert_eq!(result.tee_attestation, Some(attestation));
        
        // Test with execution time
        let time = 123;
        let result = ValidationResult::new(tx_hash.clone(), ValidationStatus::Valid, validator_id.clone(), signature.clone())
            .with_execution_time(time);
        assert_eq!(result.execution_time_ms, time);
        
        // Test with security level
        let result = ValidationResult::new(tx_hash.clone(), ValidationStatus::Valid, validator_id.clone(), signature.clone())
            .with_security_level(SecurityLevel::Full);
        assert_eq!(result.security_level, SecurityLevel::Full);
    }
    
    #[test]
    fn test_validation_tracker() {
        let mut tracker = ValidationTracker::new();
        let tx_hash = vec![1, 2, 3, 4];
        
        // Configure security levels
        tracker.configure_security_levels(100);
        assert_eq!(tracker.validators_required(SecurityLevel::Minimal), 1);
        assert_eq!(tracker.validators_required(SecurityLevel::Basic), 15); // 15% of 100
        assert_eq!(tracker.validators_required(SecurityLevel::Strong), 34); // 34% of 100
        assert_eq!(tracker.validators_required(SecurityLevel::Full), 67); // 67% of 100
        
        // Test adding results
        for i in 0..20 {
            let validator_id = vec![i]; // Simple validator ID
            let signature = vec![i + 100]; // Simple signature
            let result = ValidationResult::new(
                tx_hash.clone(),
                ValidationStatus::Valid,
                validator_id,
                signature,
            );
            tracker.add_result(result);
        }
        
        // Test validation counts
        assert_eq!(tracker.validation_count(&tx_hash), 20);
        assert_eq!(tracker.validation_count_with_status(&tx_hash, ValidationStatus::Valid), 20);
        
        // Test security level
        assert_eq!(tracker.security_level(&tx_hash), SecurityLevel::Basic); // 20 >= 15 validators (Basic)
        assert!(tracker.has_reached_security_level(&tx_hash, SecurityLevel::Minimal));
        assert!(tracker.has_reached_security_level(&tx_hash, SecurityLevel::Basic));
        assert!(!tracker.has_reached_security_level(&tx_hash, SecurityLevel::Strong));
        assert!(!tracker.has_reached_security_level(&tx_hash, SecurityLevel::Full));
        
        // Add some different status results
        for i in 20..30 {
            let validator_id = vec![i]; // Simple validator ID
            let signature = vec![i + 100]; // Simple signature
            let result = ValidationResult::new(
                tx_hash.clone(),
                ValidationStatus::Invalid,
                validator_id,
                signature,
            );
            tracker.add_result(result);
        }
        
        // Validate counts again
        assert_eq!(tracker.validation_count(&tx_hash), 30);
        assert_eq!(tracker.validation_count_with_status(&tx_hash, ValidationStatus::Valid), 20);
        assert_eq!(tracker.validation_count_with_status(&tx_hash, ValidationStatus::Invalid), 10);
        
        // Test get validators
        let validators = tracker.get_validators(&tx_hash);
        assert_eq!(validators.len(), 30);
        
        let valid_validators = tracker.get_validators_with_status(&tx_hash, ValidationStatus::Valid);
        assert_eq!(valid_validators.len(), 20);
        
        // Test clear transaction
        tracker.clear_transaction(&tx_hash);
        assert_eq!(tracker.validation_count(&tx_hash), 0);
        assert!(tracker.get_results(&tx_hash).is_none());
        
        // Test with small validator set
        let mut small_tracker = ValidationTracker::new();
        small_tracker.configure_security_levels(4);
        
        // Verify minimum validators for each level
        assert_eq!(small_tracker.validators_required(SecurityLevel::Minimal), 1);
        assert_eq!(small_tracker.validators_required(SecurityLevel::Basic), 1); // 15% of 4 is 0.6, rounds to 1
        assert_eq!(small_tracker.validators_required(SecurityLevel::Strong), 1); // 34% of 4 is 1.36, rounds to 1
        assert_eq!(small_tracker.validators_required(SecurityLevel::Full), 2); // 67% of 4 is 2.68, rounds to 2
    }
}
