//! AevorVM: the Double DAG virtual machine core.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, GasAmount};
use aevor_core::consensus::SecurityLevel;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmConfig {
    pub max_call_depth: u32,
    pub max_memory_bytes: usize,
    pub enable_jit: bool,
    pub enable_tee: bool,
    pub default_security_level: SecurityLevel,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            max_call_depth: 64,
            max_memory_bytes: 64 * 1024 * 1024,
            enable_jit: true,
            enable_tee: true,
            default_security_level: SecurityLevel::Basic,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct VmState {
    pub gas_used: GasAmount,
    pub call_depth: u32,
    pub tee_active: bool,
}

pub struct ExecutionSession {
    pub session_id: aevor_core::primitives::Hash256,
    pub config: VmConfig,
    pub state: VmState,
}

#[allow(clippy::struct_excessive_bools)] // Each bool is an independent VM capability flag
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmCapabilities {
    pub supports_move: bool,
    pub supports_tee: bool,
    pub supports_jit: bool,
    pub supports_parallel: bool,
    pub max_gas_per_tx: GasAmount,
}

impl Default for VmCapabilities {
    fn default() -> Self {
        Self {
            supports_move: true,
            supports_tee: true,
            supports_jit: true,
            supports_parallel: true,
            max_gas_per_tx: GasAmount::from_u64(10_000_000),
        }
    }
}

pub struct ContractRegistry {
    contracts: std::collections::HashMap<[u8; 32], Vec<u8>>,
}

impl ContractRegistry {
    pub fn new() -> Self { Self { contracts: std::collections::HashMap::new() } }
    pub fn register(&mut self, address: Address, bytecode: Vec<u8>) {
        self.contracts.insert(address.0, bytecode);
    }
    pub fn get(&self, address: &Address) -> Option<&Vec<u8>> {
        self.contracts.get(&address.0)
    }
    pub fn count(&self) -> usize { self.contracts.len() }
}

impl Default for ContractRegistry {
    fn default() -> Self { Self::new() }
}

pub struct AevorVm {
    config: VmConfig,
    registry: ContractRegistry,
}

impl AevorVm {
    /// Create a new `AevorVM` with the given configuration.
    pub fn new(config: VmConfig) -> Self {
        Self { config, registry: ContractRegistry::new() }
    }
    /// The capabilities of this VM instance.
    pub fn capabilities(&self) -> VmCapabilities { VmCapabilities::default() }
    /// The VM configuration.
    pub fn config(&self) -> &VmConfig { &self.config }
    /// Register a contract at the given address.
    pub fn deploy(&mut self, address: Address, bytecode: Vec<u8>) {
        self.registry.register(address, bytecode);
    }
    /// Look up a deployed contract's bytecode.
    pub fn lookup(&self, address: &Address) -> Option<&Vec<u8>> {
        self.registry.get(address)
    }
    /// Number of deployed contracts.
    pub fn contract_count(&self) -> usize { self.registry.count() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, GasAmount};

    fn addr(n: u8) -> Address { Address([n; 32]) }

    #[test]
    fn vm_config_default_values() {
        let cfg = VmConfig::default();
        assert_eq!(cfg.max_call_depth, 64);
        assert!(cfg.enable_jit);
        assert!(cfg.enable_tee);
        assert!(cfg.max_memory_bytes > 0);
    }

    #[test]
    fn vm_capabilities_default_all_enabled() {
        let caps = VmCapabilities::default();
        assert!(caps.supports_move);
        assert!(caps.supports_tee);
        assert!(caps.supports_jit);
        assert!(caps.supports_parallel);
        assert!(caps.max_gas_per_tx.as_u64() > 0);
    }

    #[test]
    fn contract_registry_register_and_get() {
        let mut reg = ContractRegistry::new();
        reg.register(addr(1), vec![0xDE, 0xAD]);
        assert_eq!(reg.get(&addr(1)).unwrap(), &vec![0xDE, 0xAD]);
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn contract_registry_get_missing_returns_none() {
        let reg = ContractRegistry::default();
        assert!(reg.get(&addr(99)).is_none());
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn contract_registry_overwrite_on_redeploy() {
        let mut reg = ContractRegistry::new();
        reg.register(addr(1), vec![1]);
        reg.register(addr(1), vec![2, 3]);
        assert_eq!(reg.get(&addr(1)).unwrap(), &vec![2, 3]);
        assert_eq!(reg.count(), 1); // only one entry
    }

    #[test]
    fn aevor_vm_deploy_and_lookup() {
        let mut vm = AevorVm::new(VmConfig::default());
        assert_eq!(vm.contract_count(), 0);
        vm.deploy(addr(5), vec![0xFF]);
        assert_eq!(vm.contract_count(), 1);
        assert_eq!(vm.lookup(&addr(5)).unwrap(), &vec![0xFF]);
        assert!(vm.lookup(&addr(6)).is_none());
    }

    #[test]
    fn aevor_vm_capabilities_match_default() {
        let vm = AevorVm::new(VmConfig::default());
        let caps = vm.capabilities();
        assert!(caps.supports_move);
        assert_eq!(caps.max_gas_per_tx, GasAmount::from_u64(10_000_000));
    }
}
