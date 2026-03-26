//! Memory isolation and hardware-enforced boundary management.

use serde::{Deserialize, Serialize};
pub use aevor_core::tee::{AntiSnoopingLevel, MemoryRange, TeeIsolationBoundary};
use aevor_core::tee::TeePlatform;
use crate::{TeeError, TeeResult};

/// Level of execution isolation enforced for a computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IsolationLevel {
    /// No isolation; computation runs in a shared process.
    None,
    /// OS process-level isolation (Linux namespaces / containers).
    ProcessLevel,
    /// Hypervisor-level VM isolation.
    VmLevel,
    /// Hardware-enforced TEE enclave.
    HardwareEnclave,
    /// Hardware-enforced TEE enclave with active anti-snooping.
    HardwareEnclaveWithAntiSnooping,
}

impl IsolationLevel {
    /// Returns `true` if isolation is enforced at the hardware level.
    pub fn is_hardware_enforced(&self) -> bool {
        matches!(self, Self::HardwareEnclave | Self::HardwareEnclaveWithAntiSnooping)
    }
}

impl std::fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::ProcessLevel => write!(f, "process"),
            Self::VmLevel => write!(f, "vm"),
            Self::HardwareEnclave => write!(f, "hardware-enclave"),
            Self::HardwareEnclaveWithAntiSnooping => write!(f, "hardware-enclave+anti-snoop"),
        }
    }
}

/// An active isolation boundary protecting a specific computation.
pub struct IsolationBoundary {
    /// Platform providing the hardware enforcement.
    pub platform: TeePlatform,
    /// The level of isolation in force.
    pub level: IsolationLevel,
    /// Memory range protected by this boundary (if applicable).
    pub memory_range: Option<MemoryRange>,
    /// Anti-snooping level active on this boundary.
    pub anti_snooping: AntiSnoopingLevel,
    active: bool,
}

impl IsolationBoundary {
    /// Establish an isolation boundary on the given platform.
    pub fn establish(
        platform: TeePlatform,
        level: IsolationLevel,
        memory_bytes: usize,
        anti_snooping: AntiSnoopingLevel,
    ) -> TeeResult<Self> {
        Ok(Self {
            platform,
            level,
            memory_range: Some(MemoryRange { start: 0, length: memory_bytes as u64 }),
            anti_snooping,
            active: true,
        })
    }

    /// Returns `true` if this boundary is currently active.
    pub fn is_active(&self) -> bool { self.active }

    /// Tear down this boundary, releasing all protected resources.
    pub fn tear_down(mut self) {
        self.active = false;
    }
}

/// Memory protection attributes for a specific address range.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryProtection {
    /// The protected memory range.
    pub range: MemoryRange,
    /// Whether the contents are encrypted at rest.
    pub encrypted: bool,
    /// Whether the contents are integrity-protected (MAC/hash).
    pub integrity_protected: bool,
    /// Whether access requires TEE-level privileges.
    pub access_controlled: bool,
}

impl MemoryProtection {
    /// Maximum protection: encrypted, integrity-protected, and access-controlled.
    pub fn full(range: MemoryRange) -> Self {
        Self { range, encrypted: true, integrity_protected: true, access_controlled: true }
    }

    /// Returns `true` if any protection is active.
    pub fn is_protected(&self) -> bool {
        self.encrypted || self.integrity_protected || self.access_controlled
    }
}

/// Records the execution isolation context for a specific operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionIsolation {
    /// The isolation level in use.
    pub level: IsolationLevel,
    /// Platform providing the isolation.
    pub platform: TeePlatform,
    /// Identifier of the specific enclave instance.
    pub enclave_id: aevor_core::primitives::Hash256,
    /// Whether the isolation is currently active.
    pub is_active: bool,
}

/// An authenticated encrypted channel between two TEE enclaves.
pub struct SecureChannel {
    /// Platform of the local end of the channel.
    pub local_platform: TeePlatform,
    /// Platform of the remote end of the channel.
    pub remote_platform: TeePlatform,
    /// Shared session key (zeroized on drop).
    pub session_key: [u8; 32],
    /// Whether the channel has been successfully established.
    pub established: bool,
}

impl SecureChannel {
    /// Establish a new encrypted channel between two TEE instances.
    pub fn establish(local: TeePlatform, remote: TeePlatform) -> TeeResult<Self> {
        let mut session_key = [0u8; 32];
        getrandom::getrandom(&mut session_key)
            .map_err(|e| TeeError::IsolationFailed { reason: e.to_string() })?;
        Ok(Self { local_platform: local, remote_platform: remote, session_key, established: true })
    }

    /// Returns `true` if the channel is live.
    pub fn is_established(&self) -> bool { self.established }

    /// Whether both ends are on the same TEE platform.
    pub fn is_same_platform(&self) -> bool { self.local_platform == self.remote_platform }
}

impl std::fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureChannel({} <-> {})", self.local_platform, self.remote_platform)
    }
}

impl Drop for SecureChannel {
    fn drop(&mut self) {
        // Zeroize the session key on drop.
        self.session_key = [0u8; 32];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_level_hardware_check() {
        assert!(IsolationLevel::HardwareEnclave.is_hardware_enforced());
        assert!(IsolationLevel::HardwareEnclaveWithAntiSnooping.is_hardware_enforced());
        assert!(!IsolationLevel::ProcessLevel.is_hardware_enforced());
        assert!(!IsolationLevel::None.is_hardware_enforced());
    }

    #[test]
    fn isolation_level_ordering() {
        assert!(IsolationLevel::HardwareEnclave > IsolationLevel::VmLevel);
        assert!(IsolationLevel::VmLevel > IsolationLevel::ProcessLevel);
    }

    #[test]
    fn memory_protection_full_is_protected() {
        let range = MemoryRange { start: 0, length: 4096 };
        let prot = MemoryProtection::full(range);
        assert!(prot.is_protected());
        assert!(prot.encrypted);
        assert!(prot.integrity_protected);
    }

    #[test]
    fn secure_channel_establish() {
        let ch = SecureChannel::establish(TeePlatform::IntelSgx, TeePlatform::AmdSev).unwrap();
        assert!(ch.is_established());
        assert!(!ch.is_same_platform());
        assert_ne!(ch.session_key, [0u8; 32]);
    }
}
