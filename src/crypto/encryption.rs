use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key as AesKey, Nonce as AesNonce,
};
use chacha20poly1305::{
    aead::Aead as ChaChaAead,
    ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use std::fmt;
use serde::{Deserialize, Serialize};

use crate::crypto::EncryptionAlgorithm;
use crate::error::{AevorError, Result};

/// Represents encrypted data
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Encryption algorithm used
    algorithm: EncryptionAlgorithm,
    
    /// Encrypted data
    data: Vec<u8>,
    
    /// Nonce or initialization vector
    nonce: Vec<u8>,
    
    /// Authentication tag, if applicable
    tag: Option<Vec<u8>>,
    
    /// Ephemeral public key, for key exchange
    ephemeral_public_key: Option<Vec<u8>>,
}

impl EncryptedData {
    /// Creates a new encrypted data container
    pub fn new(
        algorithm: EncryptionAlgorithm,
        data: Vec<u8>,
        nonce: Vec<u8>,
        tag: Option<Vec<u8>>,
        ephemeral_public_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            algorithm,
            data,
            nonce,
            tag,
            ephemeral_public_key,
        }
    }
    
    /// Gets the encryption algorithm
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }
    
    /// Gets the encrypted data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    
    /// Gets the nonce or initialization vector
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
    
    /// Gets the authentication tag, if any
    pub fn tag(&self) -> Option<&[u8]> {
        self.tag.as_deref()
    }
    
    /// Gets the ephemeral public key, if any
    pub fn ephemeral_public_key(&self) -> Option<&[u8]> {
        self.ephemeral_public_key.as_deref()
    }
    
    /// Serializes the encrypted data to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Add algorithm
        result.push(algorithm_to_byte(self.algorithm));
        
        // Add nonce length and nonce
        result.extend_from_slice(&(self.nonce.len() as u16).to_le_bytes());
        result.extend_from_slice(&self.nonce);
        
        // Add tag if present
        if let Some(tag) = &self.tag {
            result.push(1); // Tag present
            result.extend_from_slice(&(tag.len() as u16).to_le_bytes());
            result.extend_from_slice(tag);
        } else {
            result.push(0); // No tag
        }
        
        // Add ephemeral public key if present
        if let Some(key) = &self.ephemeral_public_key {
            result.push(1); // Key present
            result.extend_from_slice(&(key.len() as u16).to_le_bytes());
            result.extend_from_slice(key);
        } else {
            result.push(0); // No key
        }
        
        // Add data length and data
        result.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.data);
        
        result
    }
    
    /// Deserializes encrypted data from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(AevorError::crypto(
                "Invalid encrypted data".into(),
                "Empty byte array".into(),
                None,
            ));
        }
        
        let mut pos = 0;
        
        // Read algorithm
        let algorithm = byte_to_algorithm(bytes[pos])?;
        pos += 1;
        
        // Read nonce
        if pos + 2 > bytes.len() {
            return Err(AevorError::crypto(
                "Invalid encrypted data".into(),
                "Insufficient bytes for nonce length".into(),
                None,
            ));
        }
        let nonce_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        
        if pos + nonce_len > bytes.len() {
            return Err(AevorError::crypto(
                "Invalid encrypted data".into(),
                "Insufficient bytes for nonce".into(),
                None,
            ));
        }
        let nonce = bytes[pos..pos + nonce_len].to_vec();
        pos += nonce_len;
        
        // Read tag if present
        if pos >= bytes.len() {
            return Err(AevorError::crypto(
                "Invalid encrypted data".into(),
                "Insufficient bytes for tag presence".into(),
                None,
            ));
        }
        let tag_present = bytes[pos] == 1;
        pos += 1;
        
        let tag = if tag_present {
            if pos + 2 > bytes.len() {
                return Err(AevorError::crypto(
                    "Invalid encrypted data".into(),
                    "Insufficient bytes for tag length".into(),
                    None,
                ));
            }
            let tag_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            pos += 2;
            
            if pos + tag_len > bytes.len() {
                return Err(AevorError::crypto(
                    "Invalid encrypted data".into(),
                    "Insufficient bytes for tag".into(),
                    None,
                ));
            }
            let tag = bytes[pos..pos + tag_len].to_vec();
            pos += tag_len;
            
            Some(tag)
        } else {
            None
        };
        
        // Read ephemeral public key if present
        if pos >= bytes.len() {
            return Err(AevorError::crypto(
                "Invalid encrypted data".into(),
                "Insufficient bytes for key presence".into(),
                None,
            ));
        }
        let key_present = bytes[pos] == 1;
        pos += 1;
        
        let ephemeral_public_key = if key_present {
            if pos + 2 > bytes.len() {
                return Err(AevorError::crypto(
                    "Invalid encrypted data".into(),
                    "Insufficient bytes for key length".into(),
                    None,
                ));
            }
            let key_len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            pos += 2;
            
            if pos + key_len > bytes.len() {
                return Err(AevorError::crypto(
                    "Invalid encrypted data".into(),
                    "Insufficient bytes for key".into(),
                    None,
                ));
            }
            let key = bytes[pos..pos + key_len].to_vec();
            pos += key_len;
            
            Some(key)
        } else {
            None
        };
        
        // Read data
        if pos + 4 > bytes.len() {
            return Err(AevorError::crypto(
                "Invalid encrypted data".into(),
                "Insufficient bytes for data length".into(),
                None,
            ));
        }
        let data_len = u32::from_le_bytes([
            bytes[pos],
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
        ]) as usize;
        pos += 4;
        
        if pos + data_len > bytes.len() {
            return Err(AevorError::crypto(
                "Invalid encrypted data".into(),
                "Insufficient bytes for data".into(),
                None,
            ));
        }
        let data = bytes[pos..pos + data_len].to_vec();
        
        Ok(Self {
            algorithm,
            data,
            nonce,
            tag,
            ephemeral_public_key,
        })
    }
}

impl fmt::Debug for EncryptedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedData")
            .field("algorithm", &self.algorithm)
            .field("data_size", &self.data.len())
            .field("nonce_size", &self.nonce.len())
            .field("has_tag", &self.tag.is_some())
            .field("has_ephemeral_key", &self.ephemeral_public_key.is_some())
            .finish()
    }
}

/// Encryption utility
pub struct EncryptionUtil;

impl EncryptionUtil {
    /// Generates a new random encryption key for the specified algorithm
    pub fn generate_key(algorithm: EncryptionAlgorithm) -> Vec<u8> {
        match algorithm {
            EncryptionAlgorithm::AES256GCM => {
                let key = Aes256Gcm::generate_key(OsRng);
                key.to_vec()
            },
            EncryptionAlgorithm::CHACHA20POLY1305 => {
                let key = ChaCha20Poly1305::generate_key(&mut OsRng);
                key.to_vec()
            },
            EncryptionAlgorithm::X25519 => {
                let secret = StaticSecret::random_from_rng(OsRng);
                secret.to_bytes().to_vec()
            },
        }
    }
    
    /// Generates a new random nonce for the specified algorithm
    pub fn generate_nonce(algorithm: EncryptionAlgorithm) -> Vec<u8> {
        match algorithm {
            EncryptionAlgorithm::AES256GCM => {
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                nonce.to_vec()
            },
            EncryptionAlgorithm::CHACHA20POLY1305 => {
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                nonce.to_vec()
            },
            EncryptionAlgorithm::X25519 => {
                // X25519 doesn't use a nonce directly, but we'll generate one for consistency
                let mut nonce = [0u8; 24];
                OsRng.fill_bytes(&mut nonce);
                nonce.to_vec()
            },
        }
    }
    
    /// Derives a public key from a private key for X25519
    pub fn derive_public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() != 32 {
            return Err(AevorError::crypto(
                "Invalid private key length".into(),
                format!("Expected 32 bytes, got {}", private_key.len()),
                None,
            ));
        }
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(private_key);
        let secret = StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret);
        
        Ok(public.to_bytes().to_vec())
    }
    
    /// Encrypts data using the specified algorithm and key
    pub fn encrypt(
        algorithm: EncryptionAlgorithm,
        key: &[u8],
        data: &[u8],
        nonce: Option<&[u8]>,
    ) -> Result<EncryptedData> {
        match algorithm {
            EncryptionAlgorithm::AES256GCM => {
                if key.len() != 32 {
                    return Err(AevorError::crypto(
                        "Invalid key length".into(),
                        format!("Expected 32 bytes, got {}", key.len()),
                        None,
                    ));
                }
                
                let aes_key = AesKey::<Aes256Gcm>::from_slice(key);
                let cipher = Aes256Gcm::new(aes_key);
                
                // Use provided nonce or generate a new one
                let nonce_vec = match nonce {
                    Some(n) => {
                        if n.len() != 12 {
                            return Err(AevorError::crypto(
                                "Invalid nonce length".into(),
                                format!("Expected 12 bytes, got {}", n.len()),
                                None,
                            ));
                        }
                        n.to_vec()
                    },
                    None => Self::generate_nonce(algorithm),
                };
                
                let aes_nonce = AesNonce::from_slice(&nonce_vec);
                
                let ciphertext = cipher.encrypt(aes_nonce, data).map_err(|e| {
                    AevorError::crypto(
                        "Encryption failed".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                Ok(EncryptedData::new(
                    algorithm,
                    ciphertext,
                    nonce_vec,
                    None,
                    None,
                ))
            },
            EncryptionAlgorithm::CHACHA20POLY1305 => {
                if key.len() != 32 {
                    return Err(AevorError::crypto(
                        "Invalid key length".into(),
                        format!("Expected 32 bytes, got {}", key.len()),
                        None,
                    ));
                }
                
                let chacha_key = ChaChaKey::from_slice(key);
                let cipher = ChaCha20Poly1305::new(chacha_key);
                
                // Use provided nonce or generate a new one
                let nonce_vec = match nonce {
                    Some(n) => {
                        if n.len() != 12 {
                            return Err(AevorError::crypto(
                                "Invalid nonce length".into(),
                                format!("Expected 12 bytes, got {}", n.len()),
                                None,
                            ));
                        }
                        n.to_vec()
                    },
                    None => Self::generate_nonce(algorithm),
                };
                
                let chacha_nonce = ChaChaNonce::from_slice(&nonce_vec);
                
                let ciphertext = cipher.encrypt(chacha_nonce, data).map_err(|e| {
                    AevorError::crypto(
                        "Encryption failed".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                Ok(EncryptedData::new(
                    algorithm,
                    ciphertext,
                    nonce_vec,
                    None,
                    None,
                ))
            },
            EncryptionAlgorithm::X25519 => {
                // For X25519, the key is the recipient's public key
                if key.len() != 32 {
                    return Err(AevorError::crypto(
                        "Invalid public key length".into(),
                        format!("Expected 32 bytes, got {}", key.len()),
                        None,
                    ));
                }
                
                // Generate an ephemeral key pair
                let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
                let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
                
                // Convert recipient's public key
                let mut recipient_bytes = [0u8; 32];
                recipient_bytes.copy_from_slice(key);
                let recipient_public = X25519PublicKey::from(recipient_bytes);
                
                // Perform Diffie-Hellman to get the shared secret
                let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
                
                // Use the shared secret to derive an encryption key
                let encryption_key = derive_encryption_key(&shared_secret.to_bytes());
                
                // Use ChaCha20Poly1305 for the actual encryption
                let chacha_key = ChaChaKey::from_slice(&encryption_key);
                let cipher = ChaCha20Poly1305::new(chacha_key);
                
                // Use provided nonce or generate a new one
                let nonce_vec = match nonce {
                    Some(n) => {
                        if n.len() != 12 {
                            return Err(AevorError::crypto(
                                "Invalid nonce length".into(),
                                format!("Expected 12 bytes, got {}", n.len()),
                                None,
                            ));
                        }
                        n.to_vec()
                    },
                    None => {
                        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                        nonce.to_vec()
                    },
                };
                
                let chacha_nonce = ChaChaNonce::from_slice(&nonce_vec);
                
                let ciphertext = cipher.encrypt(chacha_nonce, data).map_err(|e| {
                    AevorError::crypto(
                        "Encryption failed".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                Ok(EncryptedData::new(
                    algorithm,
                    ciphertext,
                    nonce_vec,
                    None,
                    Some(ephemeral_public.to_bytes().to_vec()),
                ))
            },
        }
    }
    
    /// Decrypts data using the specified algorithm and key
    pub fn decrypt(
        algorithm: EncryptionAlgorithm,
        key: &[u8],
        encrypted_data: &EncryptedData,
    ) -> Result<Vec<u8>> {
        if encrypted_data.algorithm != algorithm {
            return Err(AevorError::crypto(
                "Algorithm mismatch".into(),
                format!("Expected {:?}, got {:?}", algorithm, encrypted_data.algorithm),
                None,
            ));
        }
        
        match algorithm {
            EncryptionAlgorithm::AES256GCM => {
                if key.len() != 32 {
                    return Err(AevorError::crypto(
                        "Invalid key length".into(),
                        format!("Expected 32 bytes, got {}", key.len()),
                        None,
                    ));
                }
                
                let aes_key = AesKey::<Aes256Gcm>::from_slice(key);
                let cipher = Aes256Gcm::new(aes_key);
                
                let nonce = encrypted_data.nonce();
                if nonce.len() != 12 {
                    return Err(AevorError::crypto(
                        "Invalid nonce length".into(),
                        format!("Expected 12 bytes, got {}", nonce.len()),
                        None,
                    ));
                }
                
                let aes_nonce = AesNonce::from_slice(nonce);
                
                let plaintext = cipher.decrypt(aes_nonce, encrypted_data.data()).map_err(|e| {
                    AevorError::crypto(
                        "Decryption failed".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                Ok(plaintext)
            },
            EncryptionAlgorithm::CHACHA20POLY1305 => {
                if key.len() != 32 {
                    return Err(AevorError::crypto(
                        "Invalid key length".into(),
                        format!("Expected 32 bytes, got {}", key.len()),
                        None,
                    ));
                }
                
                let chacha_key = ChaChaKey::from_slice(key);
                let cipher = ChaCha20Poly1305::new(chacha_key);
                
                let nonce = encrypted_data.nonce();
                if nonce.len() != 12 {
                    return Err(AevorError::crypto(
                        "Invalid nonce length".into(),
                        format!("Expected 12 bytes, got {}", nonce.len()),
                        None,
                    ));
                }
                
                let chacha_nonce = ChaChaNonce::from_slice(nonce);
                
                let plaintext = cipher.decrypt(chacha_nonce, encrypted_data.data()).map_err(|e| {
                    AevorError::crypto(
                        "Decryption failed".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                Ok(plaintext)
            },
            EncryptionAlgorithm::X25519 => {
                // For X25519, the key is the recipient's private key
                if key.len() != 32 {
                    return Err(AevorError::crypto(
                        "Invalid private key length".into(),
                        format!("Expected 32 bytes, got {}", key.len()),
                        None,
                    ));
                }
                
                // Get the ephemeral public key
                let ephemeral_public_key = encrypted_data.ephemeral_public_key().ok_or_else(|| {
                    AevorError::crypto(
                        "Missing ephemeral public key".into(),
                        "X25519 encryption requires an ephemeral public key".into(),
                        None,
                    )
                })?;
                
                if ephemeral_public_key.len() != 32 {
                    return Err(AevorError::crypto(
                        "Invalid ephemeral public key length".into(),
                        format!("Expected 32 bytes, got {}", ephemeral_public_key.len()),
                        None,
                    ));
                }
                
                // Convert recipient's private key
                let mut private_bytes = [0u8; 32];
                private_bytes.copy_from_slice(key);
                let private_key = StaticSecret::from(private_bytes);
                
                // Convert ephemeral public key
                let mut ephemeral_bytes = [0u8; 32];
                ephemeral_bytes.copy_from_slice(ephemeral_public_key);
                let ephemeral_public = X25519PublicKey::from(ephemeral_bytes);
                
                // Perform Diffie-Hellman to get the shared secret
                let shared_secret = private_key.diffie_hellman(&ephemeral_public);
                
                // Use the shared secret to derive an encryption key
                let encryption_key = derive_encryption_key(&shared_secret.to_bytes());
                
                // Use ChaCha20Poly1305 for the actual decryption
                let chacha_key = ChaChaKey::from_slice(&encryption_key);
                let cipher = ChaCha20Poly1305::new(chacha_key);
                
                let nonce = encrypted_data.nonce();
                if nonce.len() != 12 {
                    return Err(AevorError::crypto(
                        "Invalid nonce length".into(),
                        format!("Expected 12 bytes, got {}", nonce.len()),
                        None,
                    ));
                }
                
                let chacha_nonce = ChaChaNonce::from_slice(nonce);
                
                let plaintext = cipher.decrypt(chacha_nonce, encrypted_data.data()).map_err(|e| {
                    AevorError::crypto(
                        "Decryption failed".into(),
                        e.to_string(),
                        None,
                    )
                })?;
                
                Ok(plaintext)
            },
        }
    }
}

/// Converts an algorithm to a byte representation
fn algorithm_to_byte(algorithm: EncryptionAlgorithm) -> u8 {
    match algorithm {
        EncryptionAlgorithm::AES256GCM => 1,
        EncryptionAlgorithm::CHACHA20POLY1305 => 2,
        EncryptionAlgorithm::X25519 => 3,
    }
}

/// Converts a byte to an algorithm
fn byte_to_algorithm(byte: u8) -> Result<EncryptionAlgorithm> {
    match byte {
        1 => Ok(EncryptionAlgorithm::AES256GCM),
        2 => Ok(EncryptionAlgorithm::CHACHA20POLY1305),
        3 => Ok(EncryptionAlgorithm::X25519),
        _ => Err(AevorError::crypto(
            "Invalid algorithm byte".into(),
            format!("Unknown algorithm byte: {}", byte),
            None,
        )),
    }
}

/// Derives an encryption key from a shared secret
fn derive_encryption_key(shared_secret: &[u8]) -> [u8; 32] {
    // Use SHA-256 to derive a key from the shared secret
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    
    // Add some fixed context information to prevent related-key attacks
    hasher.update(b"Aevor-X25519-Key-Derivation");
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_key() {
        // Generate keys for each algorithm
        let aes_key = EncryptionUtil::generate_key(EncryptionAlgorithm::AES256GCM);
        let chacha_key = EncryptionUtil::generate_key(EncryptionAlgorithm::CHACHA20POLY1305);
        let x25519_key = EncryptionUtil::generate_key(EncryptionAlgorithm::X25519);
        
        // Check key lengths
        assert_eq!(aes_key.len(), 32);
        assert_eq!(chacha_key.len(), 32);
        assert_eq!(x25519_key.len(), 32);
        
        // Keys should be different
        assert_ne!(aes_key, chacha_key);
        assert_ne!(aes_key, x25519_key);
        assert_ne!(chacha_key, x25519_key);
    }
    
    #[test]
    fn test_generate_nonce() {
        // Generate nonces for each algorithm
        let aes_nonce = EncryptionUtil::generate_nonce(EncryptionAlgorithm::AES256GCM);
        let chacha_nonce = EncryptionUtil::generate_nonce(EncryptionAlgorithm::CHACHA20POLY1305);
        let x25519_nonce = EncryptionUtil::generate_nonce(EncryptionAlgorithm::X25519);
        
        // Check nonce lengths
        assert_eq!(aes_nonce.len(), 12);
        assert_eq!(chacha_nonce.len(), 12);
        assert_eq!(x25519_nonce.len(), 24);
        
        // Nonces should be different
        assert_ne!(aes_nonce, chacha_nonce);
        
        // Generate another nonce and make sure it's different
        let aes_nonce2 = EncryptionUtil::generate_nonce(EncryptionAlgorithm::AES256GCM);
        assert_ne!(aes_nonce, aes_nonce2);
    }
    
    #[test]
    fn test_derive_public_key() {
        // Generate a private key
        let private_key = EncryptionUtil::generate_key(EncryptionAlgorithm::X25519);
        
        // Derive the public key
        let public_key = EncryptionUtil::derive_public_key(&private_key).unwrap();
        
        // Check the public key length
        assert_eq!(public_key.len(), 32);
        
        // The public key should be different from the private key
        assert_ne!(private_key, public_key);
        
        // Test with an invalid private key
        let invalid_key = vec![1, 2, 3]; // Too short
        let result = EncryptionUtil::derive_public_key(&invalid_key);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_aes_encryption_decryption() {
        let data = b"Aevor blockchain encryption test";
        
        // Generate a key
        let key = EncryptionUtil::generate_key(EncryptionAlgorithm::AES256GCM);
        
        // Encrypt the data
        let encrypted = EncryptionUtil::encrypt(
            EncryptionAlgorithm::AES256GCM,
            &key,
            data,
            None,
        ).unwrap();
        
        // Check the encrypted data
        assert_eq!(encrypted.algorithm(), EncryptionAlgorithm::AES256GCM);
        assert_ne!(encrypted.data(), data);
        assert_eq!(encrypted.nonce().len(), 12);
        assert!(encrypted.tag().is_none()); // AES-GCM includes the tag in the ciphertext
        assert!(encrypted.ephemeral_public_key().is_none());
        
        // Decrypt the data
        let decrypted = EncryptionUtil::decrypt(
            EncryptionAlgorithm::AES256GCM,
            &key,
            &encrypted,
        ).unwrap();
        
        // The decrypted data should match the original
        assert_eq!(decrypted, data);
        
        // Test with a wrong key
        let wrong_key = EncryptionUtil::generate_key(EncryptionAlgorithm::AES256GCM);
        let result = EncryptionUtil::decrypt(
            EncryptionAlgorithm::AES256GCM,
            &wrong_key,
            &encrypted,
        );
        assert!(result.is_err());
    }
}
