//! Symmetric authenticated encryption: ChaCha20-Poly1305 and AES-256-GCM.
//! NO homomorphic encryption — 1000x overhead incompatible with 200k TPS target.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A 12-byte nonce for AEAD ciphers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    /// Generate a random nonce.
    ///
    /// # Errors
    /// Returns an error if the OS random number generator fails.
    pub fn generate() -> crate::CryptoResult<Self> {
        let mut bytes = [0u8; 12];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| crate::CryptoError::EncryptionError(e.to_string()))?;
        Ok(Self(bytes))
    }
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 12]) -> Self { Self(bytes) }
}

/// A 16-byte authentication tag from AEAD encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthTag(pub [u8; 16]);

/// An encryption key (32 bytes). Zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct EncryptionKey(pub [u8; 32]);

impl EncryptionKey {
    /// Generate a random 32-byte key.
    ///
    /// # Errors
    /// Returns an error if the OS random number generator fails.
    pub fn generate() -> crate::CryptoResult<Self> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| crate::CryptoError::EncryptionError(e.to_string()))?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptionKey([REDACTED])")
    }
}

/// A decryption key — alias for `EncryptionKey` (symmetric cipher).
pub type DecryptionKey = EncryptionKey;

/// Encrypted data with authentication tag and nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// AEAD authentication tag (16 bytes).
    pub auth_tag: AuthTag,
    /// Nonce used during encryption (12 bytes).
    pub nonce: Nonce,
}

/// ChaCha20-Poly1305 AEAD cipher.
///
/// Primary encryption primitive — constant-time, no timing side channels,
/// does not require hardware AES acceleration for good performance.
pub struct ChaCha20Poly1305Cipher;

impl ChaCha20Poly1305Cipher {
    /// Encrypt `plaintext` with authenticated data `aad`.
    ///
    /// # Errors
    /// Returns an error if nonce generation fails or the cipher rejects the inputs.
    pub fn encrypt(
        key: &EncryptionKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> crate::CryptoResult<EncryptedData> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce as ChaNonce, KeyInit, AeadInPlace};

        let nonce = Nonce::generate()?;
        let k = Key::from_slice(&key.0);
        let cipher = ChaCha20Poly1305::new(k);
        let n = ChaNonce::from_slice(&nonce.0);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(n, aad, &mut buffer)
            .map_err(|e| crate::CryptoError::EncryptionError(e.to_string()))?;

        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&tag);

        Ok(EncryptedData { ciphertext: buffer, auth_tag: AuthTag(auth_tag), nonce })
    }

    /// Decrypt ciphertext and verify authentication tag.
    ///
    /// # Errors
    /// Returns an error if authentication fails (tampered ciphertext, wrong key, or wrong AAD).
    pub fn decrypt(
        key: &DecryptionKey,
        data: &EncryptedData,
        aad: &[u8],
    ) -> crate::CryptoResult<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce as ChaNonce, KeyInit, AeadInPlace};
        use chacha20poly1305::aead::generic_array::GenericArray;

        let k = Key::from_slice(&key.0);
        let cipher = ChaCha20Poly1305::new(k);
        let n = ChaNonce::from_slice(&data.nonce.0);
        // Tag is a GenericArray<u8, U16> — build from our 16-byte slice
        let tag = GenericArray::clone_from_slice(&data.auth_tag.0);

        let mut buffer = data.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(n, aad, &mut buffer, &tag)
            .map_err(|_| crate::CryptoError::EncryptionError("ChaCha20-Poly1305 decryption failed".into()))?;

        Ok(buffer)
    }
}

/// AES-256-GCM AEAD cipher.
///
/// Used when hardware AES-NI acceleration is available; otherwise prefer `ChaCha20`.
pub struct AesGcmCipher;

impl AesGcmCipher {
    /// Encrypt `plaintext` with authenticated data `aad`.
    ///
    /// # Errors
    /// Returns an error if nonce generation fails or the cipher rejects the inputs.
    pub fn encrypt(
        key: &EncryptionKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> crate::CryptoResult<EncryptedData> {
        use aes_gcm::{Aes256Gcm, Key, Nonce as AesNonce, KeyInit, AeadInPlace};

        let nonce = Nonce::generate()?;
        let k = Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(k);
        let n = AesNonce::from_slice(&nonce.0);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(n, aad, &mut buffer)
            .map_err(|e| crate::CryptoError::EncryptionError(e.to_string()))?;

        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&tag);

        Ok(EncryptedData { ciphertext: buffer, auth_tag: AuthTag(auth_tag), nonce })
    }

    /// Decrypt ciphertext and verify authentication tag.
    ///
    /// # Errors
    /// Returns an error if authentication fails (tampered ciphertext, wrong key, or wrong AAD).
    pub fn decrypt(
        key: &DecryptionKey,
        data: &EncryptedData,
        aad: &[u8],
    ) -> crate::CryptoResult<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, Key, Nonce as AesNonce, KeyInit, AeadInPlace};
        use aes_gcm::aead::generic_array::GenericArray;

        let k = Key::<Aes256Gcm>::from_slice(&key.0);
        let cipher = Aes256Gcm::new(k);
        let n = AesNonce::from_slice(&data.nonce.0);
        let tag = GenericArray::clone_from_slice(&data.auth_tag.0);

        let mut buffer = data.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(n, aad, &mut buffer, &tag)
            .map_err(|_| crate::CryptoError::EncryptionError("AES-256-GCM decryption failed".into()))?;

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_roundtrip() {
        let key = EncryptionKey::generate().unwrap();
        let plaintext = b"test plaintext for encryption";
        let aad = b"authenticated data";
        let encrypted = ChaCha20Poly1305Cipher::encrypt(&key, plaintext, aad).unwrap();
        let decrypted = ChaCha20Poly1305Cipher::decrypt(&key, &encrypted, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chacha20_wrong_aad_fails() {
        let key = EncryptionKey::generate().unwrap();
        let encrypted = ChaCha20Poly1305Cipher::encrypt(&key, b"data", b"aad").unwrap();
        assert!(ChaCha20Poly1305Cipher::decrypt(&key, &encrypted, b"wrong_aad").is_err());
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let key = EncryptionKey::generate().unwrap();
        let plaintext = b"AES-GCM test data";
        let encrypted = AesGcmCipher::encrypt(&key, plaintext, b"").unwrap();
        let decrypted = AesGcmCipher::decrypt(&key, &encrypted, b"").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_gcm_tampered_ciphertext_fails() {
        let key = EncryptionKey::generate().unwrap();
        let mut encrypted = AesGcmCipher::encrypt(&key, b"secret", b"").unwrap();
        encrypted.ciphertext[0] ^= 0xFF; // Tamper
        assert!(AesGcmCipher::decrypt(&key, &encrypted, b"").is_err());
    }

    #[test]
    fn nonce_generate_is_unique() {
        let n1 = Nonce::generate().unwrap();
        let n2 = Nonce::generate().unwrap();
        // Extremely unlikely to collide
        assert_ne!(n1.0, n2.0);
    }
}
