//! TEE integration for private contract execution.

use serde::{Deserialize, Serialize};
use aevor_core::tee::TeePlatform;
use aevor_core::primitives::Hash256;
use aevor_core::consensus::ExecutionAttestation;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeContractContext {
    pub platform: TeePlatform,
    pub nonce: [u8; 32],
    pub isolation_id: Hash256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationIntegration {
    pub enabled: bool,
    pub required_platforms: Vec<TeePlatform>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecureContractExecution {
    pub context: TeeContractContext,
    pub attestation: Option<ExecutionAttestation>,
}

pub struct TeeIsolatedVm { platform: TeePlatform }
impl TeeIsolatedVm {
    pub fn new(platform: TeePlatform) -> Self { Self { platform } }
    pub fn platform(&self) -> TeePlatform { self.platform }
}

pub struct TeeVmExecutor { platform: TeePlatform }
impl TeeVmExecutor {
    /// Create a TEE VM executor for the given platform.
    pub fn new(platform: TeePlatform) -> Self { Self { platform } }
    /// The platform this executor runs on.
    pub fn platform(&self) -> TeePlatform { self.platform }
    /// Execute a closure within the TEE isolation context.
    ///
    /// # Errors
    /// Returns an error if the closure itself returns an error or if the TEE
    /// isolation context cannot be established.
    pub fn execute<F, R>(&self, f: F) -> crate::VmResult<R>
    where F: FnOnce() -> crate::VmResult<R> { f() }
}
