//! AevorVM standard library: built-in functions available to all contracts.
//!
//! The stdlib provides crypto primitives, address utilities, event emission,
//! and TEE-specific functions without requiring an external contract call.

use serde::{Deserialize, Serialize};

/// Category of a stdlib function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StdlibCategory {
    /// Cryptographic operations (hash, verify, sign).
    Crypto,
    /// Address manipulation and validation.
    Address,
    /// Event emission to the DAG log.
    Events,
    /// TEE-specific operations (attest, seal, unseal).
    Tee,
    /// Token balance operations.
    Token,
    /// Math utilities.
    Math,
}

/// Descriptor for a single stdlib function.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StdlibFunction {
    /// Name of the function as visible to contracts.
    pub name: String,
    /// Category this function belongs to.
    pub category: StdlibCategory,
    /// Base gas cost to call this function.
    pub base_gas: u64,
    /// Whether this function requires TEE execution context.
    pub requires_tee: bool,
}

impl StdlibFunction {
    /// Create a new stdlib function descriptor.
    pub fn new(
        name: impl Into<String>,
        category: StdlibCategory,
        base_gas: u64,
        requires_tee: bool,
    ) -> Self {
        Self { name: name.into(), category, base_gas, requires_tee }
    }
}

/// Registry of all available stdlib functions.
pub struct StdlibRegistry {
    functions: Vec<StdlibFunction>,
}

impl StdlibRegistry {
    /// Build the default AEVOR stdlib registry.
    pub fn new() -> Self {
        let functions = vec![
            StdlibFunction::new("hash_blake3",         StdlibCategory::Crypto,  50,   false),
            StdlibFunction::new("verify_ed25519",      StdlibCategory::Crypto,  200,  false),
            StdlibFunction::new("verify_bls12_381",    StdlibCategory::Crypto,  800,  false),
            StdlibFunction::new("address_from_pubkey", StdlibCategory::Address, 30,   false),
            StdlibFunction::new("emit_event",          StdlibCategory::Events,  100,  false),
            StdlibFunction::new("tee_attest",          StdlibCategory::Tee,     2000, true),
            StdlibFunction::new("tee_seal",            StdlibCategory::Tee,     500,  true),
            StdlibFunction::new("tee_unseal",          StdlibCategory::Tee,     500,  true),
            StdlibFunction::new("token_balance",       StdlibCategory::Token,   50,   false),
            StdlibFunction::new("token_transfer",      StdlibCategory::Token,   300,  false),
            StdlibFunction::new("math_pow",            StdlibCategory::Math,    10,   false),
        ];
        Self { functions }
    }

    /// Look up a function by name.
    pub fn get(&self, name: &str) -> Option<&StdlibFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// All functions in a given category.
    pub fn by_category(&self, category: StdlibCategory) -> Vec<&StdlibFunction> {
        self.functions.iter().filter(|f| f.category == category).collect()
    }

    /// Total number of stdlib functions.
    pub fn count(&self) -> usize { self.functions.len() }
}

impl Default for StdlibRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_expected_count() {
        let reg = StdlibRegistry::new();
        assert!(reg.count() >= 10);
    }

    #[test]
    fn hash_blake3_is_crypto_category() {
        let reg = StdlibRegistry::new();
        let f = reg.get("hash_blake3").unwrap();
        assert_eq!(f.category, StdlibCategory::Crypto);
        assert!(!f.requires_tee);
    }

    #[test]
    fn tee_functions_require_tee() {
        let reg = StdlibRegistry::new();
        let tee_fns = reg.by_category(StdlibCategory::Tee);
        assert!(!tee_fns.is_empty());
        assert!(tee_fns.iter().all(|f| f.requires_tee));
    }

    #[test]
    fn non_tee_functions_do_not_require_tee() {
        let reg = StdlibRegistry::new();
        let crypto_fns = reg.by_category(StdlibCategory::Crypto);
        assert!(crypto_fns.iter().all(|f| !f.requires_tee));
    }

    #[test]
    fn unknown_function_returns_none() {
        let reg = StdlibRegistry::new();
        assert!(reg.get("nonexistent_function").is_none());
    }
}
