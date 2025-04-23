use std::fmt;
use ed25519_dalek::{Signer as Ed25519Signer, Verifier as Ed25519Verifier, SigningKey, VerifyingKey};
use k256::ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey, Signature as K256Signature};
use k256::ecdsa::{signature::Signer as K256Signer, signature::Verifier as K256Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::SignatureAlgorithm;
use crate::error::{AevorError, Result};

/// A digital signature
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// The signature algorithm used
    algorithm: SignatureAlgorithm,
    
    /// The signature value
    value: Vec<u8>,
}

impl Signature {
    /// Creates a new signature
    pub fn new(algorithm: SignatureAlgorithm, value: Vec<u8>) -> Self {
        Self { algorithm, value }
    }
    
    /// Gets the signature algorithm
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
    
    /// Gets the signature value as bytes
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    
    /// Gets the signature as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
    
    /// Gets the signature as a hexadecimal string
    pub fn as_hex(&self) -> String {
        hex::encode(&self.value)
    }
    
    /// Creates a signature from a hexadecimal string
    pub fn from_hex(algorithm: SignatureAlgorithm, hex_str: &str) -> Result<Self> {
        let value = hex::decode(hex_str).map_err(|e| {
            AevorError::crypto(
                "Invalid hex string".into(),
                e.to_string(),
                None,
            )
        })?;
        
        Ok(Self { algorithm, value })
    }
    
    /// Signs data with the given private key and algorithm
    pub fn sign(algorithm: SignatureAlgorithm, private_key: &[u8], data: &[u8]) -> Result<Self> {
        match algorithm {
            SignatureAlgorithm::ED25519 => {
                let signing_key = SigningKey::from_bytes(&private_key_to_bytes::<32>(private_key)?).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Ed25519 private key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let signature = signing_key.sign(data).to_bytes().to_vec();
                Ok(Self::new(algorithm, signature))
            },
            SignatureAlgorithm::Secp256k1 => {
                let signing_key = K256SigningKey::from_bytes(&private_key_to_bytes::<32>(private_key)?).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Secp256k1 private key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let signature: K256Signature = signing_key.sign(data);
                Ok(Self::new(algorithm, signature.to_vec()))
            },
            SignatureAlgorithm::BLS12_381 => {
                // BLS signature implementation will be in the BLS module
                // This is just a placeholder for the interface
                Err(AevorError::crypto(
                    "BLS signature not implemented in this module".into(),
                    "Use the BLS module for BLS signatures".into(),
                    None,
                ))
            },
        }
    }
    
    /// Verifies this signature against the given public key and data
    pub fn verify(&self, public_key: &[u8], data: &[u8]) -> Result<bool> {
        match self.algorithm {
            SignatureAlgorithm::ED25519 => {
                let verifying_key = VerifyingKey::from_bytes(&public_key_to_bytes::<32>(public_key)?).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Ed25519 public key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let sig = ed25519_dalek::Signature::from_bytes(&self.value).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Ed25519 signature".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                match verifying_key.verify(data, &sig) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            },
            SignatureAlgorithm::Secp256k1 => {
                let verifying_key = K256VerifyingKey::from_sec1_bytes(public_key).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Secp256k1 public key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let sig = K256Signature::try_from(self.value.as_slice()).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Secp256k1 signature".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                match verifying_key.verify(data, &sig) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            },
            SignatureAlgorithm::BLS12_381 => {
                // BLS verification will be in the BLS module
                Err(AevorError::crypto(
                    "BLS verification not implemented in this module".into(),
                    "Use the BLS module for BLS signatures".into(),
                    None,
                ))
            },
        }
    }
    
    /// Gets the size of the signature in bytes
    pub fn size(&self) -> usize {
        self.value.len()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({:?}, {})", self.algorithm, self.as_hex())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

/// A cryptographic key pair
#[derive(Clone)]
pub struct KeyPair {
    /// The signature algorithm used
    algorithm: SignatureAlgorithm,
    
    /// The private key
    private_key: Vec<u8>,
    
    /// The public key
    public_key: Vec<u8>,
}

impl KeyPair {
    /// Creates a new key pair with the given algorithm, private key, and public key
    pub fn new(algorithm: SignatureAlgorithm, private_key: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            private_key,
            public_key,
        }
    }
    
    /// Generates a new key pair with the given algorithm
    pub fn generate(algorithm: SignatureAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureAlgorithm::ED25519 => {
                let mut csprng = OsRng;
                let signing_key = SigningKey::generate(&mut csprng);
                let verifying_key = signing_key.verifying_key();
                
                Ok(Self {
                    algorithm,
                    private_key: signing_key.to_bytes().to_vec(),
                    public_key: verifying_key.to_bytes().to_vec(),
                })
            },
            SignatureAlgorithm::Secp256k1 => {
                let mut csprng = OsRng;
                let signing_key = K256SigningKey::random(&mut csprng);
                let verifying_key = signing_key.verifying_key();
                
                Ok(Self {
                    algorithm,
                    private_key: signing_key.to_bytes().to_vec(),
                    public_key: verifying_key.to_sec1_bytes().to_vec(),
                })
            },
            SignatureAlgorithm::BLS12_381 => {
                // BLS key generation will be in the BLS module
                Err(AevorError::crypto(
                    "BLS key generation not implemented in this module".into(),
                    "Use the BLS module for BLS keys".into(),
                    None,
                ))
            },
        }
    }
    
    /// Gets the signature algorithm
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
    
    /// Gets the private key
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
    
    /// Gets the public key
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    
    /// Signs the given data with this key pair
    pub fn sign(&self, data: &[u8]) -> Result<Signature> {
        Signature::sign(self.algorithm, &self.private_key, data)
    }
    
    /// Derives the public key from the private key
    pub fn derive_public_key(algorithm: SignatureAlgorithm, private_key: &[u8]) -> Result<Vec<u8>> {
        match algorithm {
            SignatureAlgorithm::ED25519 => {
                let signing_key = SigningKey::from_bytes(&private_key_to_bytes::<32>(private_key)?).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Ed25519 private key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let verifying_key = signing_key.verifying_key();
                Ok(verifying_key.to_bytes().to_vec())
            },
            SignatureAlgorithm::Secp256k1 => {
                let signing_key = K256SigningKey::from_bytes(&private_key_to_bytes::<32>(private_key)?).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Secp256k1 private key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let verifying_key = signing_key.verifying_key();
                Ok(verifying_key.to_sec1_bytes().to_vec())
            },
            SignatureAlgorithm::BLS12_381 => {
                // BLS key derivation will be in the BLS module
                Err(AevorError::crypto(
                    "BLS key derivation not implemented in this module".into(),
                    "Use the BLS module for BLS keys".into(),
                    None,
                ))
            },
        }
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyPair({:?}, public_key: {})", 
            self.algorithm,
            hex::encode(&self.public_key)
        )
    }
}

/// Helper function to convert a byte slice to a fixed size array
fn private_key_to_bytes<const N: usize>(key: &[u8]) -> Result<[u8; N]> {
    if key.len() != N {
        return Err(AevorError::crypto(
            "Invalid key size".into(),
            format!("Expected {} bytes, got {}", N, key.len()),
            None,
        ));
    }
    
    let mut result = [0u8; N];
    result.copy_from_slice(key);
    Ok(result)
}

/// Helper function to convert a byte slice to a fixed size array
fn public_key_to_bytes<const N: usize>(key: &[u8]) -> Result<[u8; N]> {
    if key.len() != N {
        return Err(AevorError::crypto(
            "Invalid key size".into(),
            format!("Expected {} bytes, got {}", N, key.len()),
            None,
        ));
    }
    
    let mut result = [0u8; N];
    result.copy_from_slice(key);
    Ok(result)
}

/// Utility functions for signature operations
pub mod util {
    use super::*;
    
    /// Validates a signature format without verifying it against data
    pub fn validate_signature_format(algorithm: SignatureAlgorithm, signature: &[u8]) -> bool {
        match algorithm {
            SignatureAlgorithm::ED25519 => {
                // Ed25519 signatures are 64 bytes
                signature.len() == 64
            },
            SignatureAlgorithm::Secp256k1 => {
                // Secp256k1 signatures are typically 65 or 64 bytes
                signature.len() == 64 || signature.len() == 65
            },
            SignatureAlgorithm::BLS12_381 => {
                // BLS signatures are typically 96 bytes
                signature.len() == 96
            },
        }
    }
    
    /// Validates a public key format without using it
    pub fn validate_public_key_format(algorithm: SignatureAlgorithm, public_key: &[u8]) -> bool {
        match algorithm {
            SignatureAlgorithm::ED25519 => {
                // Ed25519 public keys are 32 bytes
                public_key.len() == 32
            },
            SignatureAlgorithm::Secp256k1 => {
                // Secp256k1 public keys are 33 (compressed) or 65 (uncompressed) bytes
                public_key.len() == 33 || public_key.len() == 65
            },
            SignatureAlgorithm::BLS12_381 => {
                // BLS public keys are typically 48 bytes
                public_key.len() == 48
            },
        }
    }
    
    /// Gets the expected signature size for the given algorithm
    pub fn signature_size(algorithm: SignatureAlgorithm) -> usize {
        match algorithm {
            SignatureAlgorithm::ED25519 => 64,
            SignatureAlgorithm::Secp256k1 => 65, // DER format can vary, but 65 is typical for recoverable signatures
            SignatureAlgorithm::BLS12_381 => 96,
        }
    }
    
    /// Gets the expected public key size for the given algorithm
    pub fn public_key_size(algorithm: SignatureAlgorithm) -> usize {
        match algorithm {
            SignatureAlgorithm::ED25519 => 32,
            SignatureAlgorithm::Secp256k1 => 33, // Compressed format
            SignatureAlgorithm::BLS12_381 => 48,
        }
    }
    
    /// Gets the expected private key size for the given algorithm
    pub fn private_key_size(algorithm: SignatureAlgorithm) -> usize {
        match algorithm {
            SignatureAlgorithm::ED25519 => 32,
            SignatureAlgorithm::Secp256k1 => 32,
            SignatureAlgorithm::BLS12_381 => 32,
        }
    }
}

/// Creates a signature verifier for the given algorithm
pub fn create_verifier(algorithm: SignatureAlgorithm) -> Box<dyn SignatureVerifier> {
    match algorithm {
        SignatureAlgorithm::ED25519 => Box::new(Ed25519SignatureVerifier),
        SignatureAlgorithm::Secp256k1 => Box::new(Secp256k1SignatureVerifier),
        SignatureAlgorithm::BLS12_381 => Box::new(BlsSignatureVerifier),
    }
}

/// Creates a signature signer for the given algorithm
pub fn create_signer(algorithm: SignatureAlgorithm) -> Box<dyn SignatureSigner> {
    match algorithm {
        SignatureAlgorithm::ED25519 => Box::new(Ed25519SignatureSigner),
        SignatureAlgorithm::Secp256k1 => Box::new(Secp256k1SignatureSigner),
        SignatureAlgorithm::BLS12_381 => Box::new(BlsSignatureSigner),
    }
}

/// Trait for signature verification
pub trait SignatureVerifier: Send + Sync {
    /// Verifies a signature against the given public key and data
    fn verify(&self, signature: &[u8], public_key: &[u8], data: &[u8]) -> Result<bool>;
    
    /// Gets the signature algorithm used by this verifier
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// Trait for signature generation
pub trait SignatureSigner: Send + Sync {
    /// Signs data with the given private key
    fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
    
    /// Gets the signature algorithm used by this signer
    fn algorithm(&self) -> SignatureAlgorithm;
    
    /// Generates a new key pair
    fn generate_keypair(&self) -> Result<KeyPair>;
    
    /// Derives a public key from a private key
    fn derive_public_key(&self, private_key: &[u8]) -> Result<Vec<u8>>;
}

/// Ed25519 signature verifier implementation
struct Ed25519SignatureVerifier;

impl SignatureVerifier for Ed25519SignatureVerifier {
    fn verify(&self, signature: &[u8], public_key: &[u8], data: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(&public_key_to_bytes::<32>(public_key)?).map_err(|e| {
            AevorError::crypto(
                "Invalid Ed25519 public key".into(),
                e.to_string(),
                None,
            )
        })?;
        
        let sig = ed25519_dalek::Signature::from_bytes(signature).map_err(|e| {
            AevorError::crypto(
                "Invalid Ed25519 signature".into(),
                e.to_string(),
                None,
            )
        })?;
        
        match verifying_key.verify(data, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

/// Ed25519 signature signer implementation
struct Ed25519SignatureSigner;

impl SignatureSigner for Ed25519SignatureSigner {
    fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::from_bytes(&private_key_to_bytes::<32>(private_key)?).map_err(|e| {
            AevorError::crypto(
                "Invalid Ed25519 private key".into(),
                e.to_string(),
                None,
            )
        })?;
        
        Ok(signing_key.sign(data).to_bytes().to_vec())
    }
    
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
    
    fn generate_keypair(&self) -> Result<KeyPair> {
        KeyPair::generate(SignatureAlgorithm::ED25519)
    }
    
    fn derive_public_key(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        KeyPair::derive_public_key(SignatureAlgorithm::ED25519, private_key)
    }
}

/// Secp256k1 signature verifier implementation
struct Secp256k1SignatureVerifier;

impl SignatureVerifier for Secp256k1SignatureVerifier {
    fn verify(&self, signature: &[u8], public_key: &[u8], data: &[u8]) -> Result<bool> {
        let verifying_key = K256VerifyingKey::from_sec1_bytes(public_key).map_err(|e| {
            AevorError::crypto(
                "Invalid Secp256k1 public key".into(),
                e.to_string(),
                None,
            )
        })?;
        
        let sig = K256Signature::try_from(signature).map_err(|e| {
            AevorError::crypto(
                "Invalid Secp256k1 signature".into(),
                e.to_string(),
                None,
            )
        })?;
        
        match verifying_key.verify(data, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Secp256k1
    }
}

/// Secp256k1 signature signer implementation
struct Secp256k1SignatureSigner;

impl SignatureSigner for Secp256k1SignatureSigner {
    fn sign(&self, private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = K256SigningKey::from_bytes(&private_key_to_bytes::<32>(private_key)?).map_err(|e| {
            AevorError::crypto(
                "Invalid Secp256k1 private key".into(),
                e.to_string(),
                None,
            )
        })?;
        
        let signature: K256Signature = signing_key.sign(data);
        Ok(signature.to_vec())
    }
    
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Secp256k1
    }
    
    fn generate_keypair(&self) -> Result<KeyPair> {
        KeyPair::generate(SignatureAlgorithm::Secp256k1)
    }
    
    fn derive_public_key(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        KeyPair::derive_public_key(SignatureAlgorithm::Secp256k1, private_key)
    }
}

/// BLS signature verifier implementation (placeholder)
struct BlsSignatureVerifier;

impl SignatureVerifier for BlsSignatureVerifier {
    fn verify(&self, _signature: &[u8], _public_key: &[u8], _data: &[u8]) -> Result<bool> {
        Err(AevorError::crypto(
            "BLS verification not implemented in this module".into(),
            "Use the BLS module for BLS signatures".into(),
            None,
        ))
    }
    
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::BLS12_381
    }
}

/// BLS signature signer implementation (placeholder)
struct BlsSignatureSigner;

impl SignatureSigner for BlsSignatureSigner {
    fn sign(&self, _private_key: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
        Err(AevorError::crypto(
            "BLS signing not implemented in this module".into(),
            "Use the BLS module for BLS signatures".into(),
            None,
        ))
    }
    
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::BLS12_381
    }
    
    fn generate_keypair(&self) -> Result<KeyPair> {
        Err(AevorError::crypto(
            "BLS key generation not implemented in this module".into(),
            "Use the BLS module for BLS keys".into(),
            None,
        ))
    }
    
    fn derive_public_key(&self, _private_key: &[u8]) -> Result<Vec<u8>> {
        Err(AevorError::crypto(
            "BLS key derivation not implemented in this module".into(),
            "Use the BLS module for BLS keys".into(),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_creation() {
        // Generate a key pair
        let keypair = KeyPair::generate(SignatureAlgorithm::ED25519).unwrap();
        
        // Sign some data
        let data = b"Aevor blockchain";
        let signature = keypair.sign(data).unwrap();
        
        // Check the signature
        assert_eq!(signature.algorithm(), SignatureAlgorithm::ED25519);
        assert_eq!(signature.size(), 64); // Ed25519 signatures are 64 bytes
        
        // Verify the signature
        let result = signature.verify(keypair.public_key(), data).unwrap();
        assert!(result);
        
        // Verify with wrong data
        let wrong_data = b"Wrong data";
        let result = signature.verify(keypair.public_key(), wrong_data).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_signature_hex() {
        // Generate a key pair
        let keypair = KeyPair::generate(SignatureAlgorithm::ED25519).unwrap();
        
        // Sign some data
        let data = b"Aevor blockchain";
        let signature = keypair.sign(data).unwrap();
        
        // Convert to hex
        let hex = signature.as_hex();
        
        // Convert back from hex
        let signature2 = Signature::from_hex(SignatureAlgorithm::ED25519, &hex).unwrap();
        
        // Should be the same signature
        assert_eq!(signature, signature2);
        
        // Test with invalid hex
        let result = Signature::from_hex(SignatureAlgorithm::ED25519, "invalid");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_ed25519_keypair() {
        // Generate a key pair
        let keypair = KeyPair::generate(SignatureAlgorithm::ED25519).unwrap();
        
        // Check the key pair
        assert_eq!(keypair.algorithm(), SignatureAlgorithm::ED25519);
        assert_eq!(keypair.private_key().len(), 32); // Ed25519 private keys are 32 bytes
        assert_eq!(keypair.public_key().len(), 32); // Ed25519 public keys are 32 bytes
        
        // Derive public key from private key
        let derived_public_key = KeyPair::derive_public_key(
            SignatureAlgorithm::ED25519,
            keypair.private_key()
        ).unwrap();
        
        // Should match the original public key
        assert_eq!(derived_public_key, keypair.public_key());
    }
    
    #[test]
    fn test_secp256k1_keypair() {
        // Generate a key pair
        let keypair = KeyPair::generate(SignatureAlgorithm::Secp256k1).unwrap();
        
        // Check the key pair
        assert_eq!(keypair.algorithm(), SignatureAlgorithm::Secp256k1);
        assert_eq!(keypair.private_key().len(), 32); // Secp256k1 private keys are 32 bytes
        
        // Public key length depends on format (compressed or uncompressed)
        assert!(keypair.public_key().len() == 33 || keypair.public_key().len() == 65);
        
        // Derive public key from private key
        let derived_public_key = KeyPair::derive_public_key(
            SignatureAlgorithm::Secp256k1,
            keypair.private_key()
        ).unwrap();
        
        // Should match the original public key
        assert_eq!(derived_public_key, keypair.public_key());
    }
    
    #[test]
    fn test_signature_utilities() {
        // Test signature format validation
        let valid_ed25519 = vec![0; 64];
        assert!(util::validate_signature_format(SignatureAlgorithm::ED25519, &valid_ed25519));
        
        let invalid_ed25519 = vec![0; 63];
        assert!(!util::validate_signature_format(SignatureAlgorithm::ED25519, &invalid_ed25519));
        
        let valid_secp256k1 = vec![0; 65];
        assert!(util::validate_signature_format(SignatureAlgorithm::Secp256k1, &valid_secp256k1));
        
        // Test public key format validation
        let valid_ed25519_pk = vec![0; 32];
        assert!(util::validate_public_key_format(SignatureAlgorithm::ED25519, &valid_ed25519_pk));
        
        let invalid_ed25519_pk = vec![0; 31];
        assert!(!util::validate_public_key_format(SignatureAlgorithm::ED25519, &invalid_ed25519_pk));
        
        let valid_secp256k1_pk = vec![0; 33];
        assert!(util::validate_public_key_format(SignatureAlgorithm::Secp256k1, &valid_secp256k1_pk));
        
        // Test size utilities
        assert_eq!(util::signature_size(SignatureAlgorithm::ED25519), 64);
        assert_eq!(util::public_key_size(SignatureAlgorithm::ED25519), 32);
        assert_eq!(util::private_key_size(SignatureAlgorithm::ED25519), 32);
    }
    
    #[test]
    fn test_verifier_trait() {
        // Create a verifier
        let verifier = create_verifier(SignatureAlgorithm::ED25519);
        
        // Generate a key pair
        let keypair = KeyPair::generate(SignatureAlgorithm::ED25519).unwrap();
        
        // Sign some data
        let data = b"Aevor blockchain";
        let signature = keypair.sign(data).unwrap();
        
        // Verify with the verifier
        let result = verifier.verify(signature.value(), keypair.public_key(), data).unwrap();
        assert!(result);
        
        // Verify with wrong data
        let wrong_data = b"Wrong data";
        let result = verifier.verify(signature.value(), keypair.public_key(), wrong_data).unwrap();
        assert!(!result);
    }
    
    #[test]
    fn test_signer_trait() {
        // Create a signer
        let signer = create_signer(SignatureAlgorithm::ED25519);
        
        // Generate a key pair using the signer
        let keypair = signer.generate_keypair().unwrap();
        
        // Sign some data
        let data = b"Aevor blockchain";
        let signature = signer.sign(keypair.private_key(), data).unwrap();
        
        // Create a verifier
        let verifier = create_verifier(SignatureAlgorithm::ED25519);
        
        // Verify the signature
        let result = verifier.verify(&signature, keypair.public_key(), data).unwrap();
        assert!(result);
    }
    
    #[test]
    fn test_cross_algorithm_signatures() {
        // Generate Ed25519 and Secp256k1 key pairs
        let ed25519_keypair = KeyPair::generate(SignatureAlgorithm::ED25519).unwrap();
        let secp256k1_keypair = KeyPair::generate(SignatureAlgorithm::Secp256k1).unwrap();
        
        // Sign with Ed25519
        let data = b"Aevor blockchain";
        let ed25519_signature = ed25519_keypair.sign(data).unwrap();
        
        // Sign with Secp256k1
        let secp256k1_signature = secp256k1_keypair.sign(data).unwrap();
        
        // Verify Ed25519 signature
        let result = ed25519_signature.verify(ed25519_keypair.public_key(), data).unwrap();
        assert!(result);
        
        // Verify Secp256k1 signature
        let result = secp256k1_signature.verify(secp256k1_keypair.public_key(), data).unwrap();
        assert!(result);
        
        // Try to verify Ed25519 signature with Secp256k1 key (should fail)
        let result = ed25519_signature.verify(secp256k1_keypair.public_key(), data);
        assert!(result.is_err());
    }
}
