use std::fmt;
use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use k256::ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use rand_core::OsRng as RandOsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};

use crate::crypto::SignatureAlgorithm;
use crate::crypto::signature::Signature;
use crate::error::{AevorError, Result};

/// Represents a public key
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Algorithm used for this key
    pub algorithm: SignatureAlgorithm,
    
    /// Key data
    pub key: Vec<u8>,
    
    /// Key ID (usually a hash of the key)
    pub id: String,
}

impl PublicKey {
    /// Creates a new public key
    pub fn new(algorithm: SignatureAlgorithm, key: Vec<u8>) -> Self {
        // Generate ID from the key
        let id = generate_key_id(&key);
        
        Self {
            algorithm,
            key,
            id,
        }
    }
    
    /// Verifies a signature against this public key
    pub fn verify(&self, signature: &Signature, data: &[u8]) -> Result<bool> {
        if signature.algorithm() != self.algorithm {
            return Err(AevorError::crypto(
                "Signature algorithm mismatch".into(),
                format!("Expected {:?}, got {:?}", self.algorithm, signature.algorithm()),
                None,
            ));
        }
        
        match self.algorithm {
            SignatureAlgorithm::ED25519 => {
                let verifying_key = Ed25519VerifyingKey::from_bytes(&self.key).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Ed25519 public key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes()).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Ed25519 signature".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                verifying_key.verify(data, &sig).map_err(|e| {
                    AevorError::crypto(
                        "Signature verification failed".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                Ok(true)
            },
            SignatureAlgorithm::Secp256k1 => {
                let verifying_key = K256VerifyingKey::from_sec1_bytes(&self.key).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Secp256k1 public key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let sig = k256::ecdsa::Signature::from_slice(signature.as_bytes()).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Secp256k1 signature".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                verifying_key.verify(data, &sig).map_err(|e| {
                    AevorError::crypto(
                        "Signature verification failed".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                Ok(true)
            },
            SignatureAlgorithm::BLS12_381 => {
                // BLS signature verification will be in the BLS module
                Err(AevorError::crypto(
                    "BLS signature not implemented in this module".into(),
                    "Use the BLS module for BLS signatures".into(),
                    None,
                ))
            },
        }
    }
    
    /// Gets the public key as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
    
    /// Gets the public key as a hexadecimal string
    pub fn as_hex(&self) -> String {
        hex::encode(&self.key)
    }
    
    /// Creates a public key from a hexadecimal string
    pub fn from_hex(algorithm: SignatureAlgorithm, hex_str: &str) -> Result<Self> {
        let key = hex::decode(hex_str).map_err(|e| {
            AevorError::crypto(
                "Invalid hex string".into(),
                e.to_string(),
                None,
            )
        })?;
        
        Ok(Self::new(algorithm, key))
    }
    
    /// Derives an address from the public key
    pub fn derive_address(&self) -> Vec<u8> {
        match self.algorithm {
            SignatureAlgorithm::ED25519 => {
                // For Ed25519, we simply use the key bytes
                self.key.clone()
            },
            SignatureAlgorithm::Secp256k1 => {
                // For Secp256k1, we follow Ethereum's addressing scheme
                // Keccak-256 hash of the public key, then take the last 20 bytes
                use sha3::{Digest, Keccak256};
                
                let mut hasher = Keccak256::new();
                hasher.update(&self.key);
                let result = hasher.finalize();
                
                // Take the last 20 bytes
                result[12..].to_vec()
            },
            SignatureAlgorithm::BLS12_381 => {
                // For BLS, we'll use a different scheme, similar to Ed25519
                self.key.clone()
            },
        }
    }
    
    /// Gets the key ID
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("algorithm", &self.algorithm)
            .field("id", &self.id)
            .field("key", &format_args!("{}", hex::encode(&self.key)))
            .finish()
    }
}

/// Represents a private key with security features
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    /// Algorithm used for this key
    pub algorithm: SignatureAlgorithm,
    
    /// Key data (sensitive)
    #[zeroize(skip)]
    key: Vec<u8>,
    
    /// Key ID (usually derived from the corresponding public key)
    pub id: String,
}

impl PrivateKey {
    /// Creates a new private key
    pub fn new(algorithm: SignatureAlgorithm, key: Vec<u8>) -> Self {
        // Generate ID from the public key
        let public_key = Self::derive_public_key(algorithm, &key).expect("Failed to derive public key");
        let id = public_key.id;
        
        Self {
            algorithm,
            key,
            id,
        }
    }
    
    /// Generates a new private key
    pub fn generate(algorithm: SignatureAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureAlgorithm::ED25519 => {
                let signing_key = Ed25519SigningKey::generate(&mut OsRng);
                let private_key = signing_key.to_bytes().to_vec();
                Ok(Self::new(algorithm, private_key))
            },
            SignatureAlgorithm::Secp256k1 => {
                let signing_key = K256SigningKey::random(&mut OsRng);
                let private_key = signing_key.to_bytes().to_vec();
                Ok(Self::new(algorithm, private_key))
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
    
    /// Derives the corresponding public key
    pub fn derive_public_key(algorithm: SignatureAlgorithm, private_key: &[u8]) -> Result<PublicKey> {
        match algorithm {
            SignatureAlgorithm::ED25519 => {
                let signing_key = Ed25519SigningKey::from_bytes(&private_key_to_bytes::<32>(private_key)?).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Ed25519 private key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let verifying_key = Ed25519VerifyingKey::from(&signing_key);
                let public_key = verifying_key.to_bytes().to_vec();
                
                Ok(PublicKey::new(algorithm, public_key))
            },
            SignatureAlgorithm::Secp256k1 => {
                let signing_key = K256SigningKey::from_bytes(&private_key_to_bytes::<32>(private_key)?).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Secp256k1 private key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let verifying_key = K256VerifyingKey::from(&signing_key);
                let public_key = verifying_key.to_sec1_bytes().to_vec();
                
                Ok(PublicKey::new(algorithm, public_key))
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
    
    /// Gets the private key's corresponding public key
    pub fn public_key(&self) -> Result<PublicKey> {
        Self::derive_public_key(self.algorithm, &self.key)
    }
    
    /// Signs data with this private key
    pub fn sign(&self, data: &[u8]) -> Result<Signature> {
        match self.algorithm {
            SignatureAlgorithm::ED25519 => {
                let signing_key = Ed25519SigningKey::from_bytes(&private_key_to_bytes::<32>(&self.key)?).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Ed25519 private key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let signature = signing_key.sign(data).to_bytes().to_vec();
                Ok(Signature::new(self.algorithm, signature))
            },
            SignatureAlgorithm::Secp256k1 => {
                let signing_key = K256SigningKey::from_bytes(&private_key_to_bytes::<32>(&self.key)?).map_err(|e| {
                    AevorError::crypto(
                        "Invalid Secp256k1 private key".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                let signature = signing_key.sign(data);
                Ok(Signature::new(self.algorithm, signature.to_vec()))
            },
            SignatureAlgorithm::BLS12_381 => {
                // BLS signature generation will be in the BLS module
                Err(AevorError::crypto(
                    "BLS signature not implemented in this module".into(),
                    "Use the BLS module for BLS signatures".into(),
                    None,
                ))
            },
        }
    }
    
    /// Gets the private key as bytes (be careful with this!)
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
    
    /// Gets the private key as a hexadecimal string (be careful with this!)
    pub fn as_hex(&self) -> String {
        hex::encode(&self.key)
    }
    
    /// Creates a private key from a hexadecimal string
    pub fn from_hex(algorithm: SignatureAlgorithm, hex_str: &str) -> Result<Self> {
        let key = hex::decode(hex_str).map_err(|e| {
            AevorError::crypto(
                "Invalid hex string".into(),
                e.to_string(),
                None,
            )
        })?;
        
        Ok(Self::new(algorithm, key))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm)
            .field("id", &self.id)
            .field("key", &"*****")
            .finish()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Zero out the key bytes when dropped
        for byte in &mut self.key {
            *byte = 0;
        }
    }
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

/// Represents an encrypted key for storage
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// Key ID
    pub id: String,
    
    /// Algorithm
    pub algorithm: SignatureAlgorithm,
    
    /// Encrypted key data
    pub encrypted_data: Vec<u8>,
    
    /// Salt for key derivation
    pub salt: Vec<u8>,
    
    /// Nonce for encryption
    pub nonce: Vec<u8>,
}

impl EncryptedKey {
    /// Encrypts a private key with a password
    pub fn encrypt(private_key: &PrivateKey, password: &str) -> Result<Self> {
        // Generate a salt for key derivation
        let salt = SaltString::generate(&mut RandOsRng);
        
        // Derive a key from the password
        let argon2 = Argon2::default();
        let mut derived_key = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut derived_key)
            .map_err(|e| {
                AevorError::crypto(
                    "Password hashing failed".into(),
                    e.to_string(),
                    None,
                )
            })?;
        
        // Generate a nonce for encryption
        let nonce_bytes: [u8; 12] = rand::random();
        
        // Encrypt the private key
        let key = Key::<Aes256Gcm>::from_slice(&derived_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted_data = cipher.encrypt(nonce, private_key.as_bytes().as_ref())
            .map_err(|e| {
                AevorError::crypto(
                    "Encryption failed".into(),
                    e.to_string(),
                    None,
                )
            })?;
        
        Ok(Self {
            id: private_key.id.clone(),
            algorithm: private_key.algorithm,
            encrypted_data,
            salt: salt.as_str().as_bytes().to_vec(),
            nonce: nonce_bytes.to_vec(),
        })
    }
    
    /// Decrypts to a private key with a password
    pub fn decrypt(&self, password: &str) -> Result<PrivateKey> {
        // Derive a key from the password
        let argon2 = Argon2::default();
        let mut derived_key = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), &self.salt, &mut derived_key)
            .map_err(|e| {
                AevorError::crypto(
                    "Password hashing failed".into(),
                    e.to_string(),
                    None,
                )
            })?;
        
        // Decrypt the private key
        let key = Key::<Aes256Gcm>::from_slice(&derived_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&self.nonce);
        
        let decrypted_data = cipher.decrypt(nonce, self.encrypted_data.as_ref())
            .map_err(|e| {
                AevorError::crypto(
                    "Decryption failed".into(),
                    e.to_string(),
                    None,
                )
            })?;
        
        Ok(PrivateKey::new(self.algorithm, decrypted_data))
    }
}

impl fmt::Debug for EncryptedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedKey")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field("encrypted_data", &format_args!("{} bytes", self.encrypted_data.len()))
            .field("salt", &format_args!("{} bytes", self.salt.len()))
            .field("nonce", &format_args!("{} bytes", self.nonce.len()))
            .finish()
    }
}

/// Represents a key pair (public and private keys)
#[derive(Clone)]
pub struct KeyPair {
    /// Public key
    pub public_key: PublicKey,
    
    /// Private key
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// Creates a new key pair
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Result<Self> {
        // Verify that the keys match
        if public_key.id != private_key.id {
            return Err(AevorError::crypto(
                "Key mismatch".into(),
                "Public and private keys do not correspond".into(),
                None,
            ));
        }
        
        Ok(Self {
            public_key,
            private_key,
        })
    }
    
    /// Generates a new key pair
    pub fn generate(algorithm: SignatureAlgorithm) -> Result<Self> {
        let private_key = PrivateKey::generate(algorithm)?;
        let public_key = private_key.public_key()?;
        
        Ok(Self {
            public_key,
            private_key,
        })
    }
    
    /// Gets the key pair's algorithm
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.public_key.algorithm
    }
    
    /// Signs data with the private key
    pub fn sign(&self, data: &[u8]) -> Result<Signature> {
        self.private_key.sign(data)
    }
    
    /// Verifies a signature with the public key
    pub fn verify(&self, signature: &Signature, data: &[u8]) -> Result<bool> {
        self.public_key.verify(signature, data)
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .field("private_key", &format_args!("[REDACTED]"))
            .finish()
    }
}

/// Key manager for secure key management
pub struct KeyManager {
    /// Storage directory
    storage_dir: PathBuf,
    
    /// In-memory cache of loaded keys
    key_cache: Mutex<HashMap<String, PrivateKey>>,
}

impl KeyManager {
    /// Creates a new key manager
    pub fn new<P: AsRef<Path>>(storage_dir: P) -> Result<Self> {
        let storage_dir = storage_dir.as_ref().to_path_buf();
        
        // Create directory if it doesn't exist
        if !storage_dir.exists() {
            fs::create_dir_all(&storage_dir).map_err(|e| {
                AevorError::io(e)
            })?;
        }
        
        Ok(Self {
            storage_dir,
            key_cache: Mutex::new(HashMap::new()),
        })
    }
    
    /// Generates a new key pair
    pub fn generate_keypair(&self, algorithm: SignatureAlgorithm) -> Result<KeyPair> {
        KeyPair::generate(algorithm)
    }
    
    /// Stores a private key encrypted with a password
    pub fn store_key(&self, private_key: &PrivateKey, password: &str) -> Result<()> {
        let encrypted_key = EncryptedKey::encrypt(private_key, password)?;
        
        // Serialize the encrypted key
        let json = serde_json::to_string_pretty(&encrypted_key).map_err(|e| {
            AevorError::serialization(format!("Failed to serialize key: {}", e))
        })?;
        
        // Write to file
        let file_path = self.key_path(&encrypted_key.id);
        fs::write(&file_path, json).map_err(|e| {
            AevorError::io(e)
        })?;
        
        // Add to cache
        let mut cache = self.key_cache.lock().unwrap();
        cache.insert(encrypted_key.id.clone(), private_key.clone());
        
        Ok(())
    }
    
    /// Loads a private key with a password
    pub fn load_key(&self, key_id: &str, password: &str) -> Result<PrivateKey> {
        // Check cache first
        {
            let cache = self.key_cache.lock().unwrap();
            if let Some(key) = cache.get(key_id) {
                return Ok(key.clone());
            }
        }
        
        // Load from file
        let file_path = self.key_path(key_id);
        if !file_path.exists() {
            return Err(AevorError::crypto(
                "Key not found".into(),
                format!("Key with ID {} not found", key_id),
                None,
            ));
        }
        
        let json = fs::read_to_string(&file_path).map_err(|e| {
            AevorError::io(e)
        })?;
        
        let encrypted_key: EncryptedKey = serde_json::from_str(&json).map_err(|e| {
            AevorError::deserialization(format!("Failed to deserialize key: {}", e))
        })?;
        
        // Decrypt the key
        let private_key = encrypted_key.decrypt(password)?;
        
        // Add to cache
        let mut cache = self.key_cache.lock().unwrap();
        cache.insert(key_id.to_string(), private_key.clone());
        
        Ok(private_key)
    }
    
    /// Lists all stored keys
    pub fn list_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        
        for entry in fs::read_dir(&self.storage_dir).map_err(|e| AevorError::io(e))? {
            let entry = entry.map_err(|e| AevorError::io(e))?;
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                if let Some(stem) = path.file_stem() {
                    if let Some(key_id) = stem.to_str() {
                        keys.push(key_id.to_string());
                    }
                }
            }
        }
        
        Ok(keys)
    }
    
    /// Deletes a stored key
    pub fn delete_key(&self, key_id: &str) -> Result<()> {
        let file_path = self.key_path(key_id);
        
        if file_path.exists() {
            fs::remove_file(&file_path).map_err(|e| {
                AevorError::io(e)
            })?;
            
            // Remove from cache
            let mut cache = self.key_cache.lock().unwrap();
            cache.remove(key_id);
            
            Ok(())
        } else {
            Err(AevorError::crypto(
                "Key not found".into(),
                format!("Key with ID {} not found", key_id),
                None,
            ))
        }
    }
    
    /// Signs data with a key
    pub fn sign(&self, key_id: &str, data: &[u8]) -> Result<Signature> {
        // Get the key (must be in cache)
        let cache = self.key_cache.lock().unwrap();
        let private_key = cache.get(key_id).ok_or_else(|| {
            AevorError::crypto(
                "Key not loaded".into(),
                format!("Key with ID {} not loaded in memory", key_id),
                None,
            )
        })?;
        
        private_key.sign(data)
    }
    
    /// Clears the key cache
    pub fn clear_cache(&self) {
        let mut cache = self.key_cache.lock().unwrap();
        cache.clear();
    }
    
    /// Gets the file path for a key
    fn key_path(&self, key_id: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.json", key_id))
    }
}

impl fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyManager")
            .field("storage_dir", &self.storage_dir)
            .field("cached_keys", &{
                let cache = self.key_cache.lock().unwrap();
                cache.keys().cloned().collect::<Vec<_>>()
            })
            .finish()
    }
}

/// Generates a key ID from a key
fn generate_key_id(key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    
    let mut hasher = Sha256::new();
    hasher.update(key);
    let result = hasher.finalize();
    
    hex::encode(&result[..16])
}

/// Converts a private key to a fixed-size byte array
fn private_key_to_bytes<const N: usize>(private_key: &[u8]) -> Result<[u8; N]> {
    if private_key.len() != N {
        return Err(AevorError::crypto(
            "Invalid private key length".into(),
            format!("Expected {} bytes, got {}", N, private_key.len()),
            None,
        ));
    }
    
    let mut result = [0u8; N];
    result.copy_from_slice(private_key);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_key_generation() {
        // Test Ed25519 key generation
        let ed25519_keypair = KeyPair::generate(SignatureAlgorithm::ED25519).unwrap();
        assert_eq!(ed25519_keypair.algorithm(), SignatureAlgorithm::ED25519);
        
        // Test Secp256k1 key generation
        let secp256k1_keypair = KeyPair::generate(SignatureAlgorithm::Secp256k1).unwrap();
        assert_eq!(secp256k1_keypair.algorithm(), SignatureAlgorithm::Secp256k1);
    }
    
    #[test]
    fn test_public_key_from_private() {
        // Test Ed25519 key derivation
        let private_key = PrivateKey::generate(SignatureAlgorithm::ED25519).unwrap();
        let public_key = private_key.public_key().unwrap();
        
        assert_eq!(private_key.algorithm, public_key.algorithm);
        assert_eq!(private_key.id, public_key.id);
    }
    
    #[test]
    fn test_signature_verification() {
        // Generate a key pair
        let keypair = KeyPair::generate(SignatureAlgorithm::ED25519).unwrap();
        
        // Sign some data
        let data = b"Aevor blockchain";
        let signature = keypair.sign(data).unwrap();
        
        // Verify the signature
        assert!(keypair.verify(&signature, data).unwrap());
        
        // Verify with a different data should fail
        let different_data = b"Different data";
        assert!(!keypair.verify(&signature, different_data).unwrap());
    }
    
    #[test]
    fn test_encrypted_key() {
        // Generate a private key
        let private_key = PrivateKey::generate(SignatureAlgorithm::ED25519).unwrap();
        
        // Encrypt the key
        let password = "test password";
        let encrypted_key = EncryptedKey::encrypt(&private_key, password).unwrap();
        
        // Decrypt the key
        let decrypted_key = encrypted_key.decrypt(password).unwrap();
        
        // Should be the same key
        assert_eq!(private_key.id, decrypted_key.id);
        assert_eq!(private_key.algorithm, decrypted_key.algorithm);
        assert_eq!(private_key.as_bytes(), decrypted_key.as_bytes());
        
        // Decrypt with wrong password should fail
        let wrong_password = "wrong password";
        assert!(encrypted_key.decrypt(wrong_password).is_err());
    }   
}
