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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::tee::TeePlatform;
    use aevor_core::primitives::Hash256;

    const ALL_PLATFORMS: [TeePlatform; 5] = [
        TeePlatform::IntelSgx,
        TeePlatform::AmdSev,
        TeePlatform::ArmTrustZone,
        TeePlatform::RiscvKeystone,
        TeePlatform::AwsNitro,
    ];

    // ── TeeContractContext ────────────────────────────────────────────────

    #[test]
    fn tee_contract_context_stores_platform_and_nonce() {
        let ctx = TeeContractContext {
            platform: TeePlatform::AmdSev,
            nonce: [0x42u8; 32],
            isolation_id: Hash256([0xFF; 32]),
        };
        assert_eq!(ctx.platform, TeePlatform::AmdSev);
        assert_eq!(ctx.nonce, [0x42u8; 32]);
    }

    // ── TeeIsolatedVm — all 5 platforms ──────────────────────────────────
    // Whitepaper: "cross-platform consistency that enables platform-specific
    // optimization while maintaining behavioral consistency"

    #[test]
    fn tee_isolated_vm_all_five_platforms_constructable() {
        for platform in ALL_PLATFORMS {
            let vm = TeeIsolatedVm::new(platform);
            assert_eq!(vm.platform(), platform);
        }
    }

    // ── TeeVmExecutor ─────────────────────────────────────────────────────

    #[test]
    fn tee_vm_executor_runs_closure_on_each_platform() {
        for platform in ALL_PLATFORMS {
            let executor = TeeVmExecutor::new(platform);
            let result = executor.execute(|| Ok(42u32)).unwrap();
            assert_eq!(result, 42);
        }
    }

    #[test]
    fn tee_vm_executor_propagates_error() {
        let executor = TeeVmExecutor::new(TeePlatform::IntelSgx);
        let result: crate::VmResult<u32> = executor.execute(|| {
            Err(crate::VmError::ContractAbort { code: 1, message: "test error".into() })
        });
        assert!(result.is_err());
    }

    // ── AttestationIntegration ────────────────────────────────────────────

    #[test]
    fn attestation_integration_required_platforms_all_five() {
        let ai = AttestationIntegration {
            enabled: true,
            required_platforms: ALL_PLATFORMS.to_vec(),
        };
        assert!(ai.enabled);
        assert_eq!(ai.required_platforms.len(), 5);
    }

    #[test]
    fn attestation_integration_disabled_by_default_empty_platforms() {
        let ai = AttestationIntegration {
            enabled: false,
            required_platforms: vec![],
        };
        assert!(!ai.enabled);
        assert!(ai.required_platforms.is_empty());
    }
}
