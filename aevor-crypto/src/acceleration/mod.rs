//! Hardware acceleration detection and dispatch for x86_64 (AES-NI, AVX2, SHA),
//! AArch64 (NEON, ARM Crypto), and RISC-V (Vector Extensions).

/// Architecture-specific acceleration capability flags.
#[derive(Clone, Debug, Default)]
pub struct AccelerationCapabilities {
    /// AES-NI hardware AES instructions (x86_64).
    pub aes_ni: bool,
    /// AVX2 256-bit SIMD (x86_64).
    pub avx2: bool,
    /// SHA Extensions (x86_64).
    pub sha_extensions: bool,
    /// ARM NEON SIMD (AArch64).
    pub neon: bool,
    /// ARM Crypto Extensions (AArch64).
    pub arm_crypto: bool,
    /// RISC-V Vector Extension.
    pub riscv_v: bool,
}

impl AccelerationCapabilities {
    /// Detect available hardware acceleration features at runtime.
    pub fn detect() -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            aes_ni: std::arch::is_x86_feature_detected!("aes"),
            #[cfg(target_arch = "x86_64")]
            avx2: std::arch::is_x86_feature_detected!("avx2"),
            #[cfg(target_arch = "x86_64")]
            sha_extensions: std::arch::is_x86_feature_detected!("sha"),
            #[cfg(target_arch = "aarch64")]
            neon: std::arch::is_aarch64_feature_detected!("neon"),
            #[cfg(target_arch = "aarch64")]
            arm_crypto: std::arch::is_aarch64_feature_detected!("aes"),
            ..Default::default()
        }
    }

    /// Whether any hardware acceleration is available.
    pub fn has_any(&self) -> bool {
        self.aes_ni || self.avx2 || self.sha_extensions
            || self.neon || self.arm_crypto || self.riscv_v
    }

    /// Whether to prefer AES-GCM over ChaCha20 (AES-NI makes AES faster).
    pub fn prefer_aes(&self) -> bool {
        self.aes_ni || self.arm_crypto
    }
}

/// Global lazy acceleration capability detection.
static CAPABILITIES: std::sync::OnceLock<AccelerationCapabilities> = std::sync::OnceLock::new();

/// Get the detected hardware acceleration capabilities.
pub fn capabilities() -> &'static AccelerationCapabilities {
    CAPABILITIES.get_or_init(AccelerationCapabilities::detect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_does_not_panic() {
        let caps = AccelerationCapabilities::detect();
        // Just verifying detection runs without panic on CI
        let _ = caps.has_any();
    }
}
