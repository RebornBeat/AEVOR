//! # TEE Platform Types
//!
//! Definitions for all supported Trusted Execution Environment platforms and
//! their associated capabilities, attestation types, and isolation boundaries.

use serde::{Deserialize, Serialize};
use crate::primitives::Hash256;

// ============================================================
// TEE PLATFORM
// ============================================================

/// Identifies a supported Trusted Execution Environment hardware platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeePlatform {
    /// Intel Software Guard Extensions (SGX).
    IntelSgx,
    /// AMD Secure Encrypted Virtualization (SEV / SEV-SNP).
    AmdSev,
    /// ARM TrustZone.
    ArmTrustZone,
    /// RISC-V Keystone enclave framework.
    RiscvKeystone,
    /// AWS Nitro Enclaves.
    AwsNitro,
}

impl TeePlatform {
    /// Returns the canonical name of this platform.
    pub fn name(&self) -> &'static str {
        match self {
            Self::IntelSgx => "Intel-SGX",
            Self::AmdSev => "AMD-SEV",
            Self::ArmTrustZone => "ARM-TrustZone",
            Self::RiscvKeystone => "RISC-V-Keystone",
            Self::AwsNitro => "AWS-Nitro",
        }
    }

    /// Returns `true` if this is an open-source / open-hardware TEE.
    pub fn is_open_hardware(&self) -> bool {
        matches!(self, Self::RiscvKeystone)
    }

    /// Returns `true` if this platform supports remote attestation.
    pub fn supports_remote_attestation(&self) -> bool {
        true // All supported platforms support remote attestation
    }

    /// Returns `true` if this platform supports memory encryption.
    pub fn supports_memory_encryption(&self) -> bool {
        matches!(self, Self::AmdSev | Self::AwsNitro | Self::IntelSgx)
    }

    /// Returns the maximum enclave memory size in bytes for this platform.
    pub fn max_enclave_memory_bytes(&self) -> usize {
        match self {
            Self::IntelSgx => 256 * 1024 * 1024,     // 256 MiB (hardware limit)
            Self::AmdSev => 128 * 1024 * 1024 * 1024, // 128 GiB (VM memory)
            Self::ArmTrustZone => 64 * 1024 * 1024,   // 64 MiB (typical)
            Self::RiscvKeystone => 256 * 1024 * 1024,  // 256 MiB (configurable)
            Self::AwsNitro => 4 * 1024 * 1024 * 1024, // 4 GiB (configurable)
        }
    }
}

impl std::fmt::Display for TeePlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================
// TEE VERSION
// ============================================================

/// Version information for a TEE platform.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TeeVersion {
    /// Platform identifier.
    pub platform: TeePlatform,
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
    /// Platform-specific security version number.
    pub svn: u32,
}

impl TeeVersion {
    /// Create a new version descriptor.
    pub fn new(platform: TeePlatform, major: u32, minor: u32, patch: u32, svn: u32) -> Self {
        Self { platform, major, minor, patch, svn }
    }
}

impl std::fmt::Display for TeeVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}.{}.{} (SVN {})",
            self.platform.name(),
            self.major, self.minor, self.patch, self.svn
        )
    }
}

// ============================================================
// PLATFORM CAPABILITIES
// ============================================================

/// Capabilities of a specific TEE platform instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    /// Platform and version.
    pub version: TeeVersion,
    /// Whether this is a production (non-debug) instance.
    pub is_production: bool,
    /// Whether cryptographic acceleration is available (AES-NI, SHA Extensions).
    pub has_crypto_acceleration: bool,
    /// Available memory for TEE operations in bytes.
    pub available_memory_bytes: usize,
    /// Number of concurrent enclaves/instances supported.
    pub max_concurrent_instances: usize,
    /// Whether remote attestation is functional.
    pub remote_attestation_available: bool,
    /// Whether SEALING (persistent encrypted storage) is available.
    pub sealing_available: bool,
}

// ============================================================
// ATTESTATION REPORT
// ============================================================

/// A platform-specific attestation report.
///
/// Provides cryptographic proof that code is running within a genuine,
/// verified TEE environment on the specified platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Platform that generated this report.
    pub platform: TeePlatform,
    /// Raw attestation report bytes from the platform SDK.
    pub raw_report: Vec<u8>,
    /// Measurement of the executing code (MRENCLAVE / equivalent).
    pub code_measurement: Hash256,
    /// Measurement of the enclave signer (MRSIGNER / equivalent).
    pub signer_measurement: Hash256,
    /// Nonce included in the report to prevent replay attacks.
    pub nonce: [u8; 32],
    /// Whether this report is from a production (non-debug) enclave.
    pub is_production: bool,
    /// Platform security version number.
    pub svn: u32,
    /// User-defined data embedded in the report (up to 64 bytes for SGX).
    pub user_data: Vec<u8>,
}

impl AttestationReport {
    /// Returns `true` if this attestation is from a production enclave.
    pub fn is_production_attested(&self) -> bool {
        self.is_production
    }

    /// Returns `true` if the report's nonce matches the expected nonce.
    pub fn nonce_matches(&self, expected: &[u8; 32]) -> bool {
        &self.nonce == expected
    }
}

// ============================================================
// ENCLAVE IDENTITY
// ============================================================

/// Cryptographic identity of an enclave instance.
///
/// Enclave identities are stable across restarts (same code + config)
/// and can be used to establish secure channels between enclaves.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnclaveIdentity {
    /// Platform this enclave runs on.
    pub platform: TeePlatform,
    /// Code measurement (identifies the enclave program).
    pub code_measurement: Hash256,
    /// Signer measurement (identifies who authorized the enclave).
    pub signer_measurement: Hash256,
    /// Product ID (distinguishes different products from same signer).
    pub product_id: u16,
    /// Security version number.
    pub svn: u32,
}

impl EnclaveIdentity {
    /// Returns `true` if `other` runs the same code from the same authorized signer.
    pub fn same_code_and_signer(&self, other: &Self) -> bool {
        self.code_measurement == other.code_measurement
            && self.signer_measurement == other.signer_measurement
    }
}

// ============================================================
// TEE SERVICE TYPE
// ============================================================

/// Classification of TEE service types available in the TEE-as-a-Service infrastructure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeServiceType {
    /// General-purpose confidential computation.
    Compute,
    /// Privacy-preserving data storage with TEE-managed keys.
    Storage,
    /// Edge content delivery with anti-snooping protection.
    EdgeDelivery,
    /// Confidential data indexing and analytics.
    Analytics,
    /// Secure application deployment and lifecycle management.
    Deployment,
    /// Multi-party computation coordination.
    MultiPartyComputation,
    /// Zero-knowledge proof generation.
    ZkProving,
    /// Cross-chain bridge operation.
    Bridge,
}

impl TeeServiceType {
    /// Returns the canonical name of this service type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Compute => "Compute",
            Self::Storage => "Storage",
            Self::EdgeDelivery => "EdgeDelivery",
            Self::Analytics => "Analytics",
            Self::Deployment => "Deployment",
            Self::MultiPartyComputation => "MPC",
            Self::ZkProving => "ZKProving",
            Self::Bridge => "Bridge",
        }
    }
}

impl std::fmt::Display for TeeServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================
// TEE ISOLATION BOUNDARY
// ============================================================

/// Describes an isolation boundary between a TEE context and the outside world.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeIsolationBoundary {
    /// The enclave that owns this boundary.
    pub enclave_id: EnclaveIdentity,
    /// Memory range protected by this boundary.
    pub protected_memory_range: Option<MemoryRange>,
    /// Whether the boundary enforces execution isolation.
    pub execution_isolated: bool,
    /// Whether the boundary enforces memory encryption.
    pub memory_encrypted: bool,
    /// Anti-snooping level active at this boundary.
    pub anti_snooping_level: AntiSnoopingLevel,
}

/// A range of memory addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRange {
    /// Starting address.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
}

/// Anti-snooping protection level for a TEE boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AntiSnoopingLevel {
    /// No anti-snooping protection.
    None,
    /// Basic protection (encrypt memory, secure channels).
    Basic,
    /// Enhanced protection (metadata shielding, traffic obfuscation).
    Enhanced,
    /// Maximum protection (hardware-level, timing attack resistance).
    Maximum,
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_platforms_support_remote_attestation() {
        let platforms = [
            TeePlatform::IntelSgx,
            TeePlatform::AmdSev,
            TeePlatform::ArmTrustZone,
            TeePlatform::RiscvKeystone,
            TeePlatform::AwsNitro,
        ];
        for p in &platforms {
            assert!(p.supports_remote_attestation());
        }
    }

    #[test]
    fn keystone_is_only_open_hardware() {
        assert!(TeePlatform::RiscvKeystone.is_open_hardware());
        assert!(!TeePlatform::IntelSgx.is_open_hardware());
        assert!(!TeePlatform::AmdSev.is_open_hardware());
    }

    #[test]
    fn sgx_memory_limit_is_256_mib() {
        assert_eq!(
            TeePlatform::IntelSgx.max_enclave_memory_bytes(),
            256 * 1024 * 1024
        );
    }

    #[test]
    fn enclave_identity_same_code_and_signer() {
        let id1 = EnclaveIdentity {
            platform: TeePlatform::IntelSgx,
            code_measurement: Hash256([1u8; 32]),
            signer_measurement: Hash256([2u8; 32]),
            product_id: 1,
            svn: 1,
        };
        let id2 = EnclaveIdentity {
            platform: TeePlatform::AmdSev, // Different platform
            code_measurement: Hash256([1u8; 32]),
            signer_measurement: Hash256([2u8; 32]),
            product_id: 1,
            svn: 2, // Different SVN
        };
        // Same code + signer despite different platform and SVN
        assert!(id1.same_code_and_signer(&id2));
    }

    #[test]
    fn attestation_report_nonce_check() {
        let nonce = [42u8; 32];
        let report = AttestationReport {
            platform: TeePlatform::AwsNitro,
            raw_report: vec![1, 2, 3],
            code_measurement: Hash256::ZERO,
            signer_measurement: Hash256::ZERO,
            nonce,
            is_production: true,
            svn: 1,
            user_data: vec![],
        };
        assert!(report.nonce_matches(&nonce));
        assert!(!report.nonce_matches(&[0u8; 32]));
    }

    #[test]
    fn anti_snooping_level_ordering() {
        assert!(AntiSnoopingLevel::None < AntiSnoopingLevel::Basic);
        assert!(AntiSnoopingLevel::Basic < AntiSnoopingLevel::Enhanced);
        assert!(AntiSnoopingLevel::Enhanced < AntiSnoopingLevel::Maximum);
    }
}
