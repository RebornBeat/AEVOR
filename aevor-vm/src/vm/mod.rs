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
    /// Create a new AevorVM with the given configuration.
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
