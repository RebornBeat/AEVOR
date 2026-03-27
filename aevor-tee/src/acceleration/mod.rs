//! Hardware acceleration integration: cryptographic offload per TEE platform.
//!
//! Each TEE platform can leverage platform-specific crypto acceleration
//! (AES-NI on `x86_64`, ARM Crypto Extensions on `AArch64`) to improve
//! throughput without sacrificing the security guarantees of the enclave.

use aevor_core::tee::TeePlatform;

/// Returns `true` if the given TEE platform has hardware crypto acceleration
/// available on the current CPU.
///
/// This performs a runtime CPU feature check. For SGX on `x86_64` it checks
/// for AES-NI; for `TrustZone` on `AArch64` it checks for ARM Crypto Extensions.
pub fn has_crypto_acceleration(platform: TeePlatform) -> bool {
    match platform {
        TeePlatform::IntelSgx => {
            #[cfg(target_arch = "x86_64")]
            return std::arch::is_x86_feature_detected!("aes");
            #[allow(unreachable_code)]
            false
        }
        TeePlatform::AmdSev => {
            // AMD SEV runs on x86_64 platforms that always have AES-NI
            #[cfg(target_arch = "x86_64")]
            return std::arch::is_x86_feature_detected!("aes");
            #[allow(unreachable_code)]
            true
        }
        TeePlatform::ArmTrustZone => {
            #[cfg(target_arch = "aarch64")]
            return std::arch::is_aarch64_feature_detected!("aes");
            #[allow(unreachable_code)]
            false
        }
        TeePlatform::RiscvKeystone => {
            // RISC-V crypto extensions are platform-dependent; conservative default.
            false
        }
        TeePlatform::AwsNitro => {
            // Nitro Enclaves run on x86_64 with AES-NI available.
            #[cfg(target_arch = "x86_64")]
            return std::arch::is_x86_feature_detected!("aes");
            #[allow(unreachable_code)]
            true
        }
    }
}

/// Hardware acceleration capabilities for a specific TEE platform instance.
#[derive(Clone, Debug)]
pub struct PlatformAcceleration {
    /// The TEE platform these capabilities belong to.
    pub platform: TeePlatform,
    /// Whether AES hardware acceleration is available.
    pub aes_hardware: bool,
    /// Whether SHA hardware acceleration is available.
    pub sha_hardware: bool,
    /// Whether SIMD (AVX2 / NEON) is available for vectorised crypto.
    pub simd_available: bool,
}

impl PlatformAcceleration {
    /// Detect acceleration capabilities for the given platform at runtime.
    pub fn detect(platform: TeePlatform) -> Self {
        let aes_hardware = has_crypto_acceleration(platform);

        #[cfg(target_arch = "x86_64")]
        let sha_hardware = std::arch::is_x86_feature_detected!("sha");
        #[cfg(not(target_arch = "x86_64"))]
        let sha_hardware = false;

        #[cfg(target_arch = "x86_64")]
        let simd_available = std::arch::is_x86_feature_detected!("avx2");
        #[cfg(target_arch = "aarch64")]
        let simd_available = std::arch::is_aarch64_feature_detected!("neon");
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let simd_available = false;

        Self { platform, aes_hardware, sha_hardware, simd_available }
    }

    /// Returns `true` if any hardware acceleration is available.
    pub fn has_any(&self) -> bool {
        self.aes_hardware || self.sha_hardware || self.simd_available
    }

    /// Returns the preferred cipher given available acceleration.
    ///
    /// If AES hardware is available, prefers AES-256-GCM over `ChaCha20`-Poly1305
    /// since AES-NI makes it significantly faster. Without hardware AES,
    /// `ChaCha20` is preferred as it has no timing side-channels in software.
    pub fn preferred_cipher(&self) -> &'static str {
        if self.aes_hardware { "aes-256-gcm" } else { "chacha20-poly1305" }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_does_not_panic_on_any_platform() {
        for platform in [
            TeePlatform::IntelSgx,
            TeePlatform::AmdSev,
            TeePlatform::ArmTrustZone,
            TeePlatform::RiscvKeystone,
            TeePlatform::AwsNitro,
        ] {
            let acc = PlatformAcceleration::detect(platform);
            let _ = acc.has_any();
            let _ = acc.preferred_cipher();
        }
    }

    #[test]
    fn keystone_has_no_assumed_acceleration() {
        // RISC-V Keystone: we conservatively report no acceleration
        let acc = PlatformAcceleration::detect(TeePlatform::RiscvKeystone);
        assert!(!acc.aes_hardware);
    }

    #[test]
    fn preferred_cipher_without_aes_is_chacha() {
        let acc = PlatformAcceleration {
            platform: TeePlatform::RiscvKeystone,
            aes_hardware: false,
            sha_hardware: false,
            simd_available: false,
        };
        assert_eq!(acc.preferred_cipher(), "chacha20-poly1305");
    }

    #[test]
    fn preferred_cipher_with_aes_is_aes_gcm() {
        let acc = PlatformAcceleration {
            platform: TeePlatform::IntelSgx,
            aes_hardware: true,
            sha_hardware: false,
            simd_available: false,
        };
        assert_eq!(acc.preferred_cipher(), "aes-256-gcm");
    }
}
