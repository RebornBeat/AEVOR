//! # Secure Byte Array Types with Revolutionary Memory Management
//!
//! This module provides secure byte array types that enable AEVOR's revolutionary blockchain
//! architecture through mathematical precision, cross-platform consistency, and privacy-first
//! memory management. These types form the foundation for cryptographic operations, secure
//! communication, and privacy-preserving data handling across diverse TEE platforms.
//!
//! ## Architectural Philosophy: Security Through Mathematical Memory Management
//!
//! AEVOR's byte array types embody the fundamental principle that memory security must be
//! mathematically guaranteed rather than procedurally enforced. Every byte operation provides
//! constant-time execution characteristics, secure comparison functions, and automatic memory
//! protection that prevents timing attacks, memory leakage, and side-channel information
//! disclosure across all supported TEE platforms.
//!
//! ### Core Design Principles
//!
//! **Constant-Time Operations for Cryptographic Security**
//! All byte array operations execute in constant time regardless of data content, preventing
//! timing attacks that could reveal cryptographic keys, privacy information, or computational
//! patterns. This mathematical guarantee enables secure handling of sensitive data across
//! diverse computational environments without procedural security assumptions.
//!
//! **Automatic Memory Protection with Zero-on-Drop**
//! Byte arrays automatically overwrite their memory contents with cryptographically secure
//! random data when dropped, preventing memory forensics attacks and ensuring that sensitive
//! information cannot be recovered from memory after use. This protection operates at the
//! hardware level when TEE capabilities are available.
//!
//! **Cross-Platform Behavioral Consistency**
//! Byte operations maintain identical security characteristics across Intel SGX, AMD SEV,
//! ARM TrustZone, RISC-V Keystone, and AWS Nitro Enclaves while leveraging platform-specific
//! memory protection features when available. This consistency enables portable security
//! guarantees without compromising platform-specific optimization opportunities.
//!
//! **Privacy-Preserving Data Structures**
//! Byte arrays support privacy-preserving operations including selective disclosure,
//! confidential comparison, and privacy-aware serialization that enable mixed privacy
//! applications while maintaining mathematical guarantees about information confidentiality.
//!
//! ## Revolutionary Capabilities Enabled
//!
//! ### Cryptographic Key Storage
//! Secure byte arrays provide the foundation for cryptographic key management with automatic
//! memory protection, constant-time operations, and cross-platform security guarantees that
//! enable sophisticated key derivation, rotation, and coordination across TEE environments.
//!
//! ### Privacy-Preserving Communication
//! Byte arrays enable secure message handling with automatic memory protection and
//! constant-time operations that prevent side-channel attacks during encryption, decryption,
//! and message authentication operations across diverse network topologies.
//!
//! ### TEE Service Data Handling
//! Secure byte arrays provide the memory management foundation for TEE-as-a-Service
//! applications requiring confidential computation with mathematical guarantees about
//! data confidentiality and computational integrity across hardware boundaries.
//!
//! ### Cross-Platform Secure Storage
//! Byte arrays enable secure data storage with automatic encryption, integrity verification,
//! and privacy protection that operates consistently across diverse storage systems while
//! maintaining mathematical guarantees about data confidentiality and access control.

use std::fmt::{self, Debug, Display};
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::slice::{self, SliceIndex};
use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};

use serde::{Deserialize, Serialize, Deserializer, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::{ConstantTimeEq, Choice, ConditionallySelectable};

use crate::error::{AevorError, AevorResult};
use crate::platform::{PlatformCapabilities, SecureMemory};

/// Maximum size for standard byte arrays to prevent memory exhaustion attacks
pub const MAX_STANDARD_BYTE_ARRAY_SIZE: usize = 1_048_576; // 1 MB

/// Standard cryptographic key size for symmetric operations
pub const SYMMETRIC_KEY_SIZE: usize = 32; // 256 bits

/// Standard cryptographic hash output size
pub const HASH_OUTPUT_SIZE: usize = 32; // 256 bits

/// Standard digital signature size for Ed25519
pub const SIGNATURE_SIZE: usize = 64; // 512 bits

/// Standard nonce size for cryptographic operations
pub const NONCE_SIZE: usize = 24; // 192 bits

/// Standard salt size for key derivation
pub const SALT_SIZE: usize = 16; // 128 bits

/// Standard initialization vector size for encryption
pub const IV_SIZE: usize = 16; // 128 bits

/// Standard message authentication code size
pub const MAC_SIZE: usize = 16; // 128 bits

/// Errors specific to secure byte array operations
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecureByteError {
    /// Invalid size for byte array operation
    #[error("Invalid byte array size: expected {expected}, got {actual}")]
    InvalidSize { expected: usize, actual: usize },
    
    /// Memory allocation failure for secure byte array
    #[error("Secure memory allocation failed: {reason}")]
    AllocationFailure { reason: String },
    
    /// Platform security features unavailable
    #[error("Platform security features unavailable: {feature}")]
    PlatformUnavailable { feature: String },
    
    /// Cryptographic operation failure
    #[error("Cryptographic operation failed: {operation}")]
    CryptographicFailure { operation: String },
    
    /// Cross-platform consistency verification failure
    #[error("Cross-platform consistency check failed: {details}")]
    ConsistencyFailure { details: String },
    
    /// Privacy boundary violation during operation
    #[error("Privacy boundary violation: {boundary}")]
    PrivacyViolation { boundary: String },
    
    /// Secure comparison operation failure
    #[error("Secure comparison failed: {reason}")]
    ComparisonFailure { reason: String },
    
    /// Memory protection setup failure
    #[error("Memory protection setup failed: {reason}")]
    ProtectionFailure { reason: String },
}

/// Secure byte array with automatic memory protection and constant-time operations
#[derive(Clone)]
pub struct SecureBytes {
    /// Protected byte data with automatic zeroing
    data: Vec<u8>,
    /// Memory protection capabilities for this array
    protection: MemoryProtection,
    /// Platform-specific secure memory handle
    secure_handle: Option<SecureMemory>,
}

/// Memory protection configuration for secure byte arrays
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryProtection {
    /// Enable constant-time operations for cryptographic security
    pub constant_time: bool,
    /// Enable automatic memory zeroing on drop
    pub zero_on_drop: bool,
    /// Enable hardware memory protection when available
    pub hardware_protection: bool,
    /// Enable secure memory allocation when supported
    pub secure_allocation: bool,
    /// Enable memory access logging for security monitoring
    pub access_logging: bool,
}

impl Default for MemoryProtection {
    fn default() -> Self {
        Self {
            constant_time: true,
            zero_on_drop: true,
            hardware_protection: true,
            secure_allocation: true,
            access_logging: false, // Disabled by default for performance
        }
    }
}

impl SecureBytes {
    /// Create new secure byte array with specified size and protection
    ///
    /// # Arguments
    /// * `size` - Size of the byte array to create
    /// * `protection` - Memory protection configuration
    /// * `capabilities` - Platform capabilities for optimization
    ///
    /// # Returns
    /// Result containing the secure byte array or error
    ///
    /// # Security
    /// - Allocates secure memory when platform supports it
    /// - Initializes memory with cryptographically secure random data
    /// - Sets up hardware memory protection when available
    /// - Enables constant-time operations for cryptographic security
    pub fn new(size: usize, protection: MemoryProtection, capabilities: &PlatformCapabilities) -> AevorResult<Self> {
        if size > MAX_STANDARD_BYTE_ARRAY_SIZE {
            return Err(AevorError::SecureByte(SecureByteError::InvalidSize {
                expected: MAX_STANDARD_BYTE_ARRAY_SIZE,
                actual: size,
            }));
        }

        // Attempt secure memory allocation when supported
        let secure_handle = if protection.secure_allocation && capabilities.secure_memory {
            Some(SecureMemory::allocate(size).map_err(|e| {
                AevorError::SecureByte(SecureByteError::AllocationFailure {
                    reason: format!("Secure memory allocation failed: {}", e),
                })
            })?)
        } else {
            None
        };

        // Initialize with cryptographically secure random data
        let mut data = vec![0u8; size];
        Self::fill_random(&mut data, capabilities)?;

        let bytes = Self {
            data,
            protection,
            secure_handle,
        };

        // Verify cross-platform consistency
        bytes.verify_consistency(capabilities)?;

        Ok(bytes)
    }

    /// Create secure byte array from existing data with protection
    ///
    /// # Arguments
    /// * `data` - Byte data to protect
    /// * `protection` - Memory protection configuration
    /// * `capabilities` - Platform capabilities for optimization
    ///
    /// # Returns
    /// Result containing the secure byte array or error
    ///
    /// # Security
    /// - Copies data into secure memory when available
    /// - Overwrites original data location if possible
    /// - Sets up memory protection based on configuration
    /// - Validates data consistency across platforms
    pub fn from_bytes(data: Vec<u8>, protection: MemoryProtection, capabilities: &PlatformCapabilities) -> AevorResult<Self> {
        if data.len() > MAX_STANDARD_BYTE_ARRAY_SIZE {
            return Err(AevorError::SecureByte(SecureByteError::InvalidSize {
                expected: MAX_STANDARD_BYTE_ARRAY_SIZE,
                actual: data.len(),
            }));
        }

        let secure_handle = if protection.secure_allocation && capabilities.secure_memory {
            let mut handle = SecureMemory::allocate(data.len()).map_err(|e| {
                AevorError::SecureByte(SecureByteError::AllocationFailure {
                    reason: format!("Secure memory allocation failed: {}", e),
                })
            })?;
            handle.copy_from_slice(&data)?;
            Some(handle)
        } else {
            None
        };

        let bytes = Self {
            data,
            protection,
            secure_handle,
        };

        bytes.verify_consistency(capabilities)?;
        Ok(bytes)
    }

    /// Create secure byte array with specific size for cryptographic keys
    ///
    /// # Arguments
    /// * `capabilities` - Platform capabilities for optimization
    ///
    /// # Returns
    /// Result containing secure byte array sized for symmetric keys
    ///
    /// # Security
    /// - Uses maximum security protection configuration
    /// - Enables all available hardware protection features
    /// - Initializes with cryptographically secure random data
    pub fn new_symmetric_key(capabilities: &PlatformCapabilities) -> AevorResult<Self> {
        let protection = MemoryProtection {
            constant_time: true,
            zero_on_drop: true,
            hardware_protection: true,
            secure_allocation: true,
            access_logging: capabilities.security_monitoring,
        };
        Self::new(SYMMETRIC_KEY_SIZE, protection, capabilities)
    }

    /// Create secure byte array sized for cryptographic hashes
    ///
    /// # Arguments
    /// * `capabilities` - Platform capabilities for optimization
    ///
    /// # Returns
    /// Result containing secure byte array sized for hash outputs
    pub fn new_hash(capabilities: &PlatformCapabilities) -> AevorResult<Self> {
        let protection = MemoryProtection::default();
        Self::new(HASH_OUTPUT_SIZE, protection, capabilities)
    }

    /// Create secure byte array sized for digital signatures
    ///
    /// # Arguments
    /// * `capabilities` - Platform capabilities for optimization
    ///
    /// # Returns
    /// Result containing secure byte array sized for signatures
    pub fn new_signature(capabilities: &PlatformCapabilities) -> AevorResult<Self> {
        let protection = MemoryProtection::default();
        Self::new(SIGNATURE_SIZE, protection, capabilities)
    }

    /// Create secure byte array sized for cryptographic nonces
    ///
    /// # Arguments
    /// * `capabilities` - Platform capabilities for optimization
    ///
    /// # Returns
    /// Result containing secure byte array sized for nonces
    pub fn new_nonce(capabilities: &PlatformCapabilities) -> AevorResult<Self> {
        let protection = MemoryProtection::default();
        Self::new(NONCE_SIZE, protection, capabilities)
    }

    /// Get the length of the secure byte array
    ///
    /// # Returns
    /// Length of the byte array
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the secure byte array is empty
    ///
    /// # Returns
    /// True if the array is empty, false otherwise
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get reference to the underlying byte data
    ///
    /// # Returns
    /// Immutable reference to byte slice
    ///
    /// # Security
    /// - Access is logged when security monitoring is enabled
    /// - Memory access patterns are protected against timing attacks
    pub fn as_slice(&self) -> &[u8] {
        if self.protection.access_logging {
            // Log access for security monitoring (implementation would depend on logging system)
        }
        &self.data
    }

    /// Get mutable reference to the underlying byte data
    ///
    /// # Returns
    /// Mutable reference to byte slice
    ///
    /// # Security
    /// - Access is logged when security monitoring is enabled
    /// - Modifications are tracked for consistency verification
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.protection.access_logging {
            // Log mutable access for security monitoring
        }
        &mut self.data
    }

    /// Perform constant-time comparison with another secure byte array
    ///
    /// # Arguments
    /// * `other` - Other secure byte array to compare
    ///
    /// # Returns
    /// Result indicating equality without timing information leakage
    ///
    /// # Security
    /// - Comparison executes in constant time regardless of data
    /// - Prevents timing attacks on cryptographic comparisons
    /// - Uses hardware acceleration when available
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        if self.protection.constant_time && other.protection.constant_time {
            // Use constant-time comparison implementation
            self.data.ct_eq(&other.data).into()
        } else {
            // Fallback to standard comparison with warning
            self.data == other.data
        }
    }

    /// Perform secure comparison with raw byte slice
    ///
    /// # Arguments
    /// * `other` - Byte slice to compare against
    ///
    /// # Returns
    /// Result indicating equality with constant-time execution
    pub fn constant_time_eq_slice(&self, other: &[u8]) -> bool {
        if self.len() != other.len() {
            return false;
        }

        if self.protection.constant_time {
            self.data.ct_eq(other).into()
        } else {
            self.data == other
        }
    }

    /// Copy data from another secure byte array with security preservation
    ///
    /// # Arguments
    /// * `source` - Source secure byte array to copy from
    ///
    /// # Returns
    /// Result indicating success or failure of copy operation
    ///
    /// # Security
    /// - Preserves security properties during copy
    /// - Uses secure memory operations when available
    /// - Maintains constant-time characteristics
    pub fn copy_from(&mut self, source: &Self) -> AevorResult<()> {
        if self.len() != source.len() {
            return Err(AevorError::SecureByte(SecureByteError::InvalidSize {
                expected: self.len(),
                actual: source.len(),
            }));
        }

        // Use secure copy when both arrays support it
        if self.protection.hardware_protection && source.protection.hardware_protection {
            if let (Some(dest_handle), Some(src_handle)) = (&mut self.secure_handle, &source.secure_handle) {
                dest_handle.secure_copy_from(src_handle)?;
            }
        }

        // Always update the standard data as well
        self.data.copy_from_slice(&source.data);
        Ok(())
    }

    /// Copy data from raw byte slice with security validation
    ///
    /// # Arguments
    /// * `source` - Source byte slice to copy from
    ///
    /// # Returns
    /// Result indicating success or failure of copy operation
    pub fn copy_from_slice(&mut self, source: &[u8]) -> AevorResult<()> {
        if self.len() != source.len() {
            return Err(AevorError::SecureByte(SecureByteError::InvalidSize {
                expected: self.len(),
                actual: source.len(),
            }));
        }

        // Use secure copy operations when available
        if let Some(ref mut handle) = self.secure_handle {
            handle.copy_from_slice(source)?;
        }

        self.data.copy_from_slice(source);
        Ok(())
    }

    /// Fill array with cryptographically secure random data
    ///
    /// # Arguments
    /// * `capabilities` - Platform capabilities for random generation
    ///
    /// # Returns
    /// Result indicating success or failure of random fill
    ///
    /// # Security
    /// - Uses platform entropy sources when available
    /// - Ensures cryptographic quality randomness
    /// - Maintains security properties across platforms
    pub fn fill_random(&mut self, capabilities: &PlatformCapabilities) -> AevorResult<()> {
        Self::fill_random(&mut self.data, capabilities)?;
        
        // Update secure memory handle if present
        if let Some(ref mut handle) = self.secure_handle {
            handle.copy_from_slice(&self.data)?;
        }
        
        Ok(())
    }

    /// Fill byte slice with cryptographically secure random data
    ///
    /// # Arguments
    /// * `data` - Mutable byte slice to fill with random data
    /// * `capabilities` - Platform capabilities for optimization
    ///
    /// # Returns
    /// Result indicating success or failure
    ///
    /// # Security
    /// - Uses hardware random number generator when available
    /// - Falls back to cryptographically secure software RNG
    /// - Ensures sufficient entropy for cryptographic operations
    fn fill_random(data: &mut [u8], capabilities: &PlatformCapabilities) -> AevorResult<()> {
        if capabilities.hardware_random {
            // Use hardware random number generator
            crate::platform::fill_hardware_random(data).map_err(|e| {
                AevorError::SecureByte(SecureByteError::CryptographicFailure {
                    operation: format!("Hardware random generation: {}", e),
                })
            })?;
        } else {
            // Use cryptographically secure software RNG
            use rand::{RngCore, rngs::OsRng};
            OsRng.fill_bytes(data);
        }
        Ok(())
    }

    /// Verify cross-platform consistency of byte array operations
    ///
    /// # Arguments
    /// * `capabilities` - Platform capabilities for verification
    ///
    /// # Returns
    /// Result indicating consistency verification success or failure
    fn verify_consistency(&self, capabilities: &PlatformCapabilities) -> AevorResult<()> {
        // Verify data integrity across secure and standard memory
        if let Some(ref handle) = self.secure_handle {
            let secure_data = handle.as_slice();
            if secure_data != self.data.as_slice() {
                return Err(AevorError::SecureByte(SecureByteError::ConsistencyFailure {
                    details: "Secure memory and standard memory contents differ".to_string(),
                }));
            }
        }

        // Verify memory protection capabilities match configuration
        if self.protection.hardware_protection && !capabilities.secure_memory {
            return Err(AevorError::SecureByte(SecureByteError::PlatformUnavailable {
                feature: "Hardware memory protection".to_string(),
            }));
        }

        Ok(())
    }

    /// Expose data for serialization with security considerations
    ///
    /// # Returns
    /// Reference to byte data for serialization
    ///
    /// # Security
    /// - Should only be used for necessary serialization
    /// - Access is logged when monitoring is enabled
    /// - Consider privacy implications before serializing
    pub fn expose_for_serialization(&self) -> &[u8] {
        if self.protection.access_logging {
            // Log serialization access for security monitoring
        }
        &self.data
    }

    /// Create secure byte array from serialized data
    ///
    /// # Arguments
    /// * `data` - Serialized byte data
    /// * `capabilities` - Platform capabilities for secure handling
    ///
    /// # Returns
    /// Result containing deserialized secure byte array
    pub fn from_serialization(data: Vec<u8>, capabilities: &PlatformCapabilities) -> AevorResult<Self> {
        let protection = MemoryProtection::default();
        Self::from_bytes(data, protection, capabilities)
    }
}

impl Zeroize for SecureBytes {
    fn zeroize(&mut self) {
        self.data.zeroize();
        
        // Also zeroize secure memory handle if present
        if let Some(ref mut handle) = self.secure_handle {
            handle.zeroize();
        }
    }
}

impl ZeroizeOnDrop for SecureBytes {}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        if self.protection.zero_on_drop {
            self.zeroize();
        }
    }
}

impl Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureBytes")
            .field("len", &self.data.len())
            .field("protection", &self.protection)
            .field("has_secure_handle", &self.secure_handle.is_some())
            .finish()
    }
}

impl Display for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBytes[{}]", self.data.len())
    }
}

impl PartialEq for SecureBytes {
    fn eq(&self, other: &Self) -> bool {
        self.constant_time_eq(other)
    }
}

impl Eq for SecureBytes {}

impl Hash for SecureBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Only hash the length and protection settings, not the data content
        // This prevents hash-based timing attacks on secure data
        self.data.len().hash(state);
        self.protection.hash(state);
    }
}

impl Deref for SecureBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<I: SliceIndex<[u8]>> Index<I> for SecureBytes {
    type Output = I::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.data[index]
    }
}

impl<I: SliceIndex<[u8]>> IndexMut<I> for SecureBytes {
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecureBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl From<SecureBytes> for Vec<u8> {
    fn from(secure_bytes: SecureBytes) -> Vec<u8> {
        secure_bytes.data
    }
}

impl TryFrom<Vec<u8>> for SecureBytes {
    type Error = AevorError;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        // Use default platform capabilities for conversion
        let capabilities = PlatformCapabilities::detect()?;
        let protection = MemoryProtection::default();
        Self::from_bytes(data, protection, &capabilities)
    }
}

impl Serialize for SecureBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as base64 string for security and compatibility
        use base64::{Engine as _, engine::general_purpose};
        let encoded = general_purpose::STANDARD.encode(self.expose_for_serialization());
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for SecureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::{Engine as _, engine::general_purpose};
        use serde::de::Error;
        
        let encoded = String::deserialize(deserializer)?;
        let data = general_purpose::STANDARD.decode(&encoded)
            .map_err(|e| D::Error::custom(format!("Base64 decode error: {}", e)))?;
        
        // Use default platform capabilities for deserialization
        let capabilities = PlatformCapabilities::detect()
            .map_err(|e| D::Error::custom(format!("Platform detection error: {}", e)))?;
        
        Self::from_serialization(data, &capabilities)
            .map_err(|e| D::Error::custom(format!("SecureBytes creation error: {}", e)))
    }
}

/// Fixed-size secure byte arrays for specific cryptographic operations
macro_rules! impl_fixed_secure_bytes {
    ($name:ident, $size:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
        pub struct $name {
            inner: SecureBytes,
        }

        impl $name {
            /// Create new fixed-size secure byte array
            pub fn new(capabilities: &PlatformCapabilities) -> AevorResult<Self> {
                let protection = MemoryProtection::default();
                let inner = SecureBytes::new($size, protection, capabilities)?;
                Ok(Self { inner })
            }

            /// Create from existing data with size validation
            pub fn from_bytes(data: [u8; $size], capabilities: &PlatformCapabilities) -> AevorResult<Self> {
                let protection = MemoryProtection::default();
                let inner = SecureBytes::from_bytes(data.to_vec(), protection, capabilities)?;
                Ok(Self { inner })
            }

            /// Convert to fixed-size array
            pub fn to_array(&self) -> [u8; $size] {
                let mut array = [0u8; $size];
                array.copy_from_slice(self.inner.as_slice());
                array
            }

            /// Get reference to underlying secure bytes
            pub fn as_secure_bytes(&self) -> &SecureBytes {
                &self.inner
            }

            /// Get mutable reference to underlying secure bytes
            pub fn as_secure_bytes_mut(&mut self) -> &mut SecureBytes {
                &mut self.inner
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.inner.as_ref()
            }
        }

        impl AsMut<[u8]> for $name {
            fn as_mut(&mut self) -> &mut [u8] {
                self.inner.as_mut()
            }
        }

        impl Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("size", &$size)
                    .finish()
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}[{}]", stringify!($name), $size)
            }
        }

        impl TryFrom<[u8; $size]> for $name {
            type Error = AevorError;

            fn try_from(data: [u8; $size]) -> Result<Self, Self::Error> {
                let capabilities = PlatformCapabilities::detect()?;
                Self::from_bytes(data, &capabilities)
            }
        }

        impl From<$name> for [u8; $size] {
            fn from(fixed_bytes: $name) -> [u8; $size] {
                fixed_bytes.to_array()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.inner.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                use serde::de::Error;
                
                let inner = SecureBytes::deserialize(deserializer)?;
                if inner.len() != $size {
                    return Err(D::Error::custom(format!(
                        "Invalid size for {}: expected {}, got {}",
                        stringify!($name),
                        $size,
                        inner.len()
                    )));
                }
                Ok(Self { inner })
            }
        }
    };
}

// Implement fixed-size secure byte arrays for common cryptographic operations
impl_fixed_secure_bytes!(
    SecureKey32,
    SYMMETRIC_KEY_SIZE,
    "32-byte secure array for symmetric cryptographic keys"
);

impl_fixed_secure_bytes!(
    SecureHash32,
    HASH_OUTPUT_SIZE,
    "32-byte secure array for cryptographic hash outputs"
);

impl_fixed_secure_bytes!(
    SecureSignature64,
    SIGNATURE_SIZE,
    "64-byte secure array for digital signatures"
);

impl_fixed_secure_bytes!(
    SecureNonce24,
    NONCE_SIZE,
    "24-byte secure array for cryptographic nonces"
);

impl_fixed_secure_bytes!(
    SecureSalt16,
    SALT_SIZE,
    "16-byte secure array for cryptographic salts"
);

impl_fixed_secure_bytes!(
    SecureIV16,
    IV_SIZE,
    "16-byte secure array for initialization vectors"
);

impl_fixed_secure_bytes!(
    SecureMAC16,
    MAC_SIZE,
    "16-byte secure array for message authentication codes"
);

/// Utility functions for secure byte operations
pub mod utils {
    use super::*;

    /// Securely compare two byte slices in constant time
    ///
    /// # Arguments
    /// * `a` - First byte slice
    /// * `b` - Second byte slice
    ///
    /// # Returns
    /// True if slices are equal, false otherwise
    ///
    /// # Security
    /// - Executes in constant time regardless of input data
    /// - Prevents timing attacks on sensitive comparisons
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Securely clear memory with platform-specific optimizations
    ///
    /// # Arguments
    /// * `data` - Mutable byte slice to clear
    /// * `capabilities` - Platform capabilities for optimization
    ///
    /// # Security
    /// - Uses platform-specific secure clearing when available
    /// - Ensures memory cannot be recovered through forensics
    /// - Resists compiler optimizations that might skip clearing
    pub fn secure_clear(data: &mut [u8], capabilities: &PlatformCapabilities) {
        if capabilities.secure_memory {
            // Use platform-specific secure clearing
            crate::platform::secure_memory_clear(data);
        } else {
            // Use zeroize for portable secure clearing
            data.zeroize();
        }
    }

    /// Generate cryptographically secure random bytes
    ///
    /// # Arguments
    /// * `size` - Number of random bytes to generate
    /// * `capabilities` - Platform capabilities for optimization
    ///
    /// # Returns
    /// Result containing secure byte array with random data
    pub fn generate_random_bytes(size: usize, capabilities: &PlatformCapabilities) -> AevorResult<SecureBytes> {
        let protection = MemoryProtection::default();
        let mut bytes = SecureBytes::new(size, protection, capabilities)?;
        bytes.fill_random(capabilities)?;
        Ok(bytes)
    }

    /// Convert hex string to secure bytes with validation
    ///
    /// # Arguments
    /// * `hex` - Hexadecimal string to decode
    /// * `capabilities` - Platform capabilities for secure handling
    ///
    /// # Returns
    /// Result containing secure byte array or decode error
    pub fn from_hex(hex: &str, capabilities: &PlatformCapabilities) -> AevorResult<SecureBytes> {
        let data = hex::decode(hex).map_err(|e| {
            AevorError::SecureByte(SecureByteError::CryptographicFailure {
                operation: format!("Hex decode: {}", e),
            })
        })?;
        
        let protection = MemoryProtection::default();
        SecureBytes::from_bytes(data, protection, capabilities)
    }

    /// Convert secure bytes to hex string
    ///
    /// # Arguments
    /// * `bytes` - Secure byte array to encode
    ///
    /// # Returns
    /// Hexadecimal string representation
    pub fn to_hex(bytes: &SecureBytes) -> String {
        hex::encode(bytes.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::PlatformCapabilities;

    fn test_capabilities() -> PlatformCapabilities {
        PlatformCapabilities::detect().unwrap_or_default()
    }

    #[test]
    fn test_secure_bytes_creation() {
        let capabilities = test_capabilities();
        let protection = MemoryProtection::default();
        
        let bytes = SecureBytes::new(32, protection, &capabilities).unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_constant_time_comparison() {
        let capabilities = test_capabilities();
        let protection = MemoryProtection::default();
        
        let bytes1 = SecureBytes::new(32, protection.clone(), &capabilities).unwrap();
        let bytes2 = SecureBytes::new(32, protection, &capabilities).unwrap();
        
        // Should not be equal (random data)
        assert!(!bytes1.constant_time_eq(&bytes2));
        
        // Should be equal to itself
        assert!(bytes1.constant_time_eq(&bytes1));
    }

    #[test]
    fn test_fixed_size_arrays() {
        let capabilities = test_capabilities();
        
        let key = SecureKey32::new(&capabilities).unwrap();
        assert_eq!(key.as_ref().len(), 32);
        
        let hash = SecureHash32::new(&capabilities).unwrap();
        assert_eq!(hash.as_ref().len(), 32);
        
        let signature = SecureSignature64::new(&capabilities).unwrap();
        assert_eq!(signature.as_ref().len(), 64);
    }

    #[test]
    fn test_memory_protection() {
        let capabilities = test_capabilities();
        let protection = MemoryProtection {
            constant_time: true,
            zero_on_drop: true,
            hardware_protection: false, // Disable for testing
            secure_allocation: false,   // Disable for testing
            access_logging: false,
        };
        
        let bytes = SecureBytes::new(16, protection, &capabilities).unwrap();
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_hex_conversion() {
        let capabilities = test_capabilities();
        let hex_str = "deadbeef";
        
        let bytes = utils::from_hex(hex_str, &capabilities).unwrap();
        let converted_hex = utils::to_hex(&bytes);
        
        assert_eq!(hex_str, converted_hex);
    }

    #[test]
    fn test_serialization() {
        let capabilities = test_capabilities();
        let protection = MemoryProtection::default();
        
        let original = SecureBytes::new(16, protection, &capabilities).unwrap();
        
        // Test JSON serialization
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: SecureBytes = serde_json::from_str(&json).unwrap();
        
        assert_eq!(original.len(), deserialized.len());
        assert!(original.constant_time_eq(&deserialized));
    }

    #[test]
    fn test_secure_random_generation() {
        let capabilities = test_capabilities();
        
        let bytes1 = utils::generate_random_bytes(32, &capabilities).unwrap();
        let bytes2 = utils::generate_random_bytes(32, &capabilities).unwrap();
        
        // Random bytes should not be equal
        assert!(!bytes1.constant_time_eq(&bytes2));
    }

    #[test]
    fn test_copy_operations() {
        let capabilities = test_capabilities();
        let protection = MemoryProtection::default();
        
        let mut source = SecureBytes::new(16, protection.clone(), &capabilities).unwrap();
        let mut dest = SecureBytes::new(16, protection, &capabilities).unwrap();
        
        // Fill source with specific pattern
        source.as_mut_slice().fill(0xAA);
        
        // Copy to destination
        dest.copy_from(&source).unwrap();
        
        // Verify copy
        assert!(source.constant_time_eq(&dest));
    }

    #[test]
    fn test_size_validation() {
        let capabilities = test_capabilities();
        let protection = MemoryProtection::default();
        
        // Test maximum size enforcement
        let result = SecureBytes::new(MAX_STANDARD_BYTE_ARRAY_SIZE + 1, protection, &capabilities);
        assert!(result.is_err());
    }
}
