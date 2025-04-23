use std::fmt;
use std::collections::HashMap;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::hash::{Hash, HashAlgorithm};
use crate::error::{AevorError, Result};

/// BLS signature scheme implementation for the Aevor blockchain
/// 
/// This module provides BLS signature functionality with signature aggregation,
/// which is essential for the Security Level Accelerator mechanism. BLS signatures
/// allow multiple signatures to be combined into a single signature, significantly
/// reducing the size of validation proofs.

/// A BLS key pair
#[derive(Clone)]
pub struct BlsKeyPair {
    /// Private key as a BLS12-381 Scalar
    private_key: Scalar,
    
    /// Public key as a G1 point
    public_key: G1Projective,
}

/// BLS public key
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsPublicKey {
    /// Public key as compressed G1 point bytes
    pub bytes: Vec<u8>,
}

/// BLS private key
#[derive(Clone, Serialize, Deserialize)]
pub struct BlsPrivateKey {
    /// Private key as scalar bytes
    pub bytes: Vec<u8>,
}

/// BLS signature
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsSignature {
    /// Signature as compressed G2 point bytes
    pub bytes: Vec<u8>,
}

/// BLS aggregate signature
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsAggregateSignature {
    /// Aggregated signature as compressed G2 point bytes
    pub bytes: Vec<u8>,
    
    /// Public keys that participated in this aggregate signature
    pub public_keys: Vec<BlsPublicKey>,
    
    /// Optional metadata about the signers
    pub metadata: HashMap<String, Vec<u8>>,
}

impl BlsKeyPair {
    /// Generates a new random BLS key pair
    pub fn random() -> Self {
        let mut rng = OsRng;
        let private_key = Scalar::random(&mut rng);
        let public_key = G1Projective::generator() * private_key;
        
        Self {
            private_key,
            public_key,
        }
    }
    
    /// Creates a key pair from an existing private key
    pub fn from_private_key(private_key: &BlsPrivateKey) -> Result<Self> {
        let scalar = scalar_from_bytes(&private_key.bytes)?;
        let public_key = G1Projective::generator() * scalar;
        
        Ok(Self {
            private_key: scalar,
            public_key,
        })
    }
    
    /// Gets the public key for this key pair
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey {
            bytes: g1_to_bytes(&self.public_key),
        }
    }
    
    /// Gets the private key for this key pair
    pub fn private_key(&self) -> BlsPrivateKey {
        BlsPrivateKey {
            bytes: scalar_to_bytes(&self.private_key),
        }
    }
    
    /// Signs a message with this key pair
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let hash_to_curve = hash_to_g2(message);
        let signature = hash_to_curve * self.private_key;
        
        BlsSignature {
            bytes: g2_to_bytes(&signature),
        }
    }
}

impl BlsPublicKey {
    /// Creates a public key from compressed bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        // Validate that the bytes can be converted to a G1 point
        let _ = g1_from_bytes(&bytes)?;
        
        Ok(Self { bytes })
    }
    
    /// Verifies a signature against this public key
    pub fn verify(&self, signature: &BlsSignature, message: &[u8]) -> Result<bool> {
        let public_key = g1_from_bytes(&self.bytes)?;
        let sig = g2_from_bytes(&signature.bytes)?;
        let hash_to_curve = hash_to_g2(message);
        
        // e(P, H(m)) == e(G, S)
        // where P is the public key, H(m) is the hash of the message to G2,
        // G is the generator, and S is the signature
        
        let g1_gen = G1Affine::generator();
        let public_key_neg = G1Affine::from(-public_key);
        
        let hash_to_curve_affine = G2Affine::from(hash_to_curve);
        let sig_affine = G2Affine::from(sig);
        
        // Check if e(P, H(m)) * e(-G, S) == 1
        // This is equivalent to e(P, H(m)) == e(G, S)
        let pairing_result = bls12_381::pairing(&public_key_neg, &hash_to_curve_affine) + bls12_381::pairing(&g1_gen, &sig_affine);
        
        Ok(pairing_result.is_identity())
    }
    
    /// Aggregates multiple public keys into a single public key
    pub fn aggregate(public_keys: &[BlsPublicKey]) -> Result<Self> {
        if public_keys.is_empty() {
            return Err(AevorError::crypto(
                "Empty public keys".into(),
                "Cannot aggregate empty public keys".into(),
                None,
            ));
        }
        
        let mut aggregate = G1Projective::identity();
        
        for public_key in public_keys {
            let pk = g1_from_bytes(&public_key.bytes)?;
            aggregate += pk;
        }
        
        Ok(Self {
            bytes: g1_to_bytes(&aggregate),
        })
    }
}

impl BlsPrivateKey {
    /// Creates a private key from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        // Validate that the bytes can be converted to a scalar
        let _ = scalar_from_bytes(&bytes)?;
        
        Ok(Self { bytes })
    }
    
    /// Generates a random private key
    pub fn random() -> Self {
        let mut rng = OsRng;
        let scalar = Scalar::random(&mut rng);
        
        Self {
            bytes: scalar_to_bytes(&scalar),
        }
    }
    
    /// Derives the public key from this private key
    pub fn to_public_key(&self) -> Result<BlsPublicKey> {
        let scalar = scalar_from_bytes(&self.bytes)?;
        let public_key = G1Projective::generator() * scalar;
        
        Ok(BlsPublicKey {
            bytes: g1_to_bytes(&public_key),
        })
    }
    
    /// Signs a message with this private key
    pub fn sign(&self, message: &[u8]) -> Result<BlsSignature> {
        let scalar = scalar_from_bytes(&self.bytes)?;
        let hash_to_curve = hash_to_g2(message);
        let signature = hash_to_curve * scalar;
        
        Ok(BlsSignature {
            bytes: g2_to_bytes(&signature),
        })
    }
}

impl BlsSignature {
    /// Creates a signature from compressed bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        // Validate that the bytes can be converted to a G2 point
        let _ = g2_from_bytes(&bytes)?;
        
        Ok(Self { bytes })
    }
    
    /// Verifies this signature against a public key and message
    pub fn verify(&self, public_key: &BlsPublicKey, message: &[u8]) -> Result<bool> {
        public_key.verify(self, message)
    }
    
    /// Aggregates multiple signatures into a single signature
    pub fn aggregate(signatures: &[BlsSignature]) -> Result<Self> {
        if signatures.is_empty() {
            return Err(AevorError::crypto(
                "Empty signatures".into(),
                "Cannot aggregate empty signatures".into(),
                None,
            ));
        }
        
        let mut aggregate = G2Projective::identity();
        
        for signature in signatures {
            let sig = g2_from_bytes(&signature.bytes)?;
            aggregate += sig;
        }
        
        Ok(Self {
            bytes: g2_to_bytes(&aggregate),
        })
    }
    
    /// Creates an aggregate signature with the provided public keys
    pub fn create_aggregate_signature(&self, public_keys: Vec<BlsPublicKey>) -> BlsAggregateSignature {
        BlsAggregateSignature {
            bytes: self.bytes.clone(),
            public_keys,
            metadata: HashMap::new(),
        }
    }
}

impl BlsAggregateSignature {
    /// Creates an aggregate signature from bytes and public keys
    pub fn new(bytes: Vec<u8>, public_keys: Vec<BlsPublicKey>) -> Result<Self> {
        // Validate that the bytes can be converted to a G2 point
        let _ = g2_from_bytes(&bytes)?;
        
        Ok(Self {
            bytes,
            public_keys,
            metadata: HashMap::new(),
        })
    }
    
    /// Adds metadata to this aggregate signature
    pub fn with_metadata(mut self, key: String, value: Vec<u8>) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Verifies this aggregate signature against a single message
    /// 
    /// This verification method is used when all signers signed the same message.
    pub fn verify_single_message(&self, message: &[u8]) -> Result<bool> {
        if self.public_keys.is_empty() {
            return Err(AevorError::crypto(
                "Empty public keys".into(),
                "Cannot verify an aggregate signature with no public keys".into(),
                None,
            ));
        }
        
        let aggregated_pk = BlsPublicKey::aggregate(&self.public_keys)?;
        let signature = BlsSignature { bytes: self.bytes.clone() };
        
        signature.verify(&aggregated_pk, message)
    }
    
    /// Verifies this aggregate signature against multiple messages
    /// 
    /// This verification method is used when each signer signed a different message.
    /// It requires the messages to be provided in the same order as the public keys.
    pub fn verify_multiple_messages(&self, messages: &[&[u8]]) -> Result<bool> {
        if self.public_keys.len() != messages.len() {
            return Err(AevorError::crypto(
                "Mismatched counts".into(),
                format!(
                    "Number of public keys ({}) does not match number of messages ({})",
                    self.public_keys.len(),
                    messages.len()
                ),
                None,
            ));
        }
        
        let sig = g2_from_bytes(&self.bytes)?;
        let sig_affine = G2Affine::from(sig);
        
        // For each (public_key, message) pair, compute e(pk, H(m))
        let mut pairing_sum = bls12_381::Gt::identity();
        
        for (i, (public_key, message)) in self.public_keys.iter().zip(messages.iter()).enumerate() {
            let pk = g1_from_bytes(&public_key.bytes)?;
            let pk_affine = G1Affine::from(pk);
            
            let hash_to_curve = hash_to_g2(message);
            let hash_to_curve_affine = G2Affine::from(hash_to_curve);
            
            pairing_sum += bls12_381::pairing(&pk_affine, &hash_to_curve_affine);
        }
        
        // Compute e(G1, sig) where G1 is the generator
        let g1_gen = G1Affine::generator();
        let sig_pairing = bls12_381::pairing(&g1_gen, &sig_affine);
        
        // Verify that the product of the pairings equals the pairing with the signature
        Ok(pairing_sum == sig_pairing)
    }
    
    /// Gets the number of signers in this aggregate signature
    pub fn signer_count(&self) -> usize {
        self.public_keys.len()
    }
    
    /// Gets a specific public key by index
    pub fn get_public_key(&self, index: usize) -> Option<&BlsPublicKey> {
        self.public_keys.get(index)
    }
    
    /// Gets metadata value by key
    pub fn get_metadata(&self, key: &str) -> Option<&Vec<u8>> {
        self.metadata.get(key)
    }
    
    /// Sets a metadata value
    pub fn set_metadata(&mut self, key: String, value: Vec<u8>) {
        self.metadata.insert(key, value);
    }
}

// Helper functions for BLS operations

/// Hash a message to a G2 point (hash-to-curve operation)
fn hash_to_g2(message: &[u8]) -> G2Projective {
    // This is a simplified implementation of hash-to-curve
    // In a production environment, a standardized hash-to-curve method should be used
    
    // Hash the message first
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    
    // Use the hash to derive a point on G2
    // This is a simplified approach and not fully secure for production
    let mut seed = [0u8; 64];
    for i in 0..32 {
        seed[i] = hash[i % 32];
        seed[i + 32] = hash[(i + 16) % 32];
    }
    
    // Try to map to a valid point
    let mut attempt = 0u8;
    loop {
        seed[0] = attempt;
        
        // Try to create a scalar from the seed
        if let Ok(scalar) = Scalar::from_bytes_wide(&seed) {
            // Return scalar * G2 generator
            return G2Projective::generator() * scalar;
        }
        
        attempt = attempt.wrapping_add(1);
        if attempt == 0 {
            // Unlikely to happen, but just in case
            seed[1] = seed[1].wrapping_add(1);
        }
    }
}

/// Convert a G1 point to compressed bytes
fn g1_to_bytes(point: &G1Projective) -> Vec<u8> {
    G1Affine::from(point).to_compressed().to_vec()
}

/// Convert bytes to a G1 point
fn g1_from_bytes(bytes: &[u8]) -> Result<G1Projective> {
    if bytes.len() != 48 {
        return Err(AevorError::crypto(
            "Invalid G1 point bytes".into(),
            format!("Expected 48 bytes, got {}", bytes.len()),
            None,
        ));
    }
    
    let mut array = [0u8; 48];
    array.copy_from_slice(bytes);
    
    let point = G1Affine::from_compressed(&array).map_err(|_| {
        AevorError::crypto(
            "Invalid G1 point bytes".into(),
            "Could not deserialize G1 point".into(),
            None,
        )
    })?;
    
    Ok(G1Projective::from(point))
}

/// Convert a G2 point to compressed bytes
fn g2_to_bytes(point: &G2Projective) -> Vec<u8> {
    G2Affine::from(point).to_compressed().to_vec()
}

/// Convert bytes to a G2 point
fn g2_from_bytes(bytes: &[u8]) -> Result<G2Projective> {
    if bytes.len() != 96 {
        return Err(AevorError::crypto(
            "Invalid G2 point bytes".into(),
            format!("Expected 96 bytes, got {}", bytes.len()),
            None,
        ));
    }
    
    let mut array = [0u8; 96];
    array.copy_from_slice(bytes);
    
    let point = G2Affine::from_compressed(&array).map_err(|_| {
        AevorError::crypto(
            "Invalid G2 point bytes".into(),
            "Could not deserialize G2 point".into(),
            None,
        )
    })?;
    
    Ok(G2Projective::from(point))
}

/// Convert a scalar to bytes
fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
    scalar.to_bytes().to_vec()
}

/// Convert bytes to a scalar
fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar> {
    if bytes.len() != 32 {
        return Err(AevorError::crypto(
            "Invalid scalar bytes".into(),
            format!("Expected 32 bytes, got {}", bytes.len()),
            None,
        ));
    }
    
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    
    let scalar = Scalar::from_bytes(&array).map_err(|_| {
        AevorError::crypto(
            "Invalid scalar bytes".into(),
            "Could not deserialize scalar".into(),
            None,
        )
    })?;
    
    Ok(scalar)
}

/// BLS threshold signature scheme
pub mod threshold {
    use super::*;
    use std::collections::HashSet;
    
    /// A BLS threshold signature scheme
    pub struct BlsThresholdScheme {
        /// Number of participants
        n: usize,
        
        /// Threshold (minimum number of signatures needed)
        t: usize,
        
        /// Coefficients for the polynomial
        coefficients: Vec<Scalar>,
    }
    
    /// A share of a threshold signature
    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct BlsThresholdShare {
        /// Index of the share (1-indexed)
        pub index: usize,
        
        /// The private key share
        pub private_key: BlsPrivateKey,
        
        /// The public key share
        pub public_key: BlsPublicKey,
    }
    
    /// A partial signature in a threshold scheme
    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct BlsPartialSignature {
        /// Index of the signer (1-indexed)
        pub index: usize,
        
        /// The signature
        pub signature: BlsSignature,
    }
    
    /// A reconstructed threshold signature
    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct BlsThresholdSignature {
        /// The reconstructed signature
        pub signature: BlsSignature,
        
        /// The participant indices that contributed to this signature
        pub participants: Vec<usize>,
    }
    
    impl BlsThresholdScheme {
        /// Creates a new threshold signature scheme
        pub fn new(n: usize, t: usize) -> Result<Self> {
            if t == 0 || t > n {
                return Err(AevorError::crypto(
                    "Invalid threshold parameters".into(),
                    format!("Threshold t ({}) must be between 1 and n ({})", t, n),
                    None,
                ));
            }
            
            let mut rng = OsRng;
            let mut coefficients = Vec::with_capacity(t);
            
            // Generate random coefficients for the polynomial
            for _ in 0..t {
                coefficients.push(Scalar::random(&mut rng));
            }
            
            Ok(Self { n, t, coefficients })
        }
        
        /// Generates shares for all participants
        pub fn generate_shares(&self) -> Vec<BlsThresholdShare> {
            let mut shares = Vec::with_capacity(self.n);
            
            for i in 1..=self.n {
                // Compute f(i) where f is the polynomial
                let x = Scalar::from(i as u64);
                let mut y = self.coefficients[0]; // Constant term
                
                // Evaluate the polynomial at x
                let mut x_pow = x;
                for j in 1..self.coefficients.len() {
                    y += self.coefficients[j] * x_pow;
                    x_pow *= x;
                }
                
                // Create the share
                let private_key = BlsPrivateKey {
                    bytes: scalar_to_bytes(&y),
                };
                
                let public_key = G1Projective::generator() * y;
                
                shares.push(BlsThresholdShare {
                    index: i,
                    private_key,
                    public_key: BlsPublicKey {
                        bytes: g1_to_bytes(&public_key),
                    },
                });
            }
            
            shares
        }
        
        /// Gets the master public key
        pub fn master_public_key(&self) -> BlsPublicKey {
            // The master public key is g * coefficient[0]
            let public_key = G1Projective::generator() * self.coefficients[0];
            
            BlsPublicKey {
                bytes: g1_to_bytes(&public_key),
            }
        }
        
        /// Reconstructs a signature from partial signatures
        pub fn reconstruct_signature(&self, partial_signatures: &[BlsPartialSignature]) -> Result<BlsThresholdSignature> {
            if partial_signatures.len() < self.t {
                return Err(AevorError::crypto(
                    "Insufficient partial signatures".into(),
                    format!(
                        "Need at least {} signatures, got {}",
                        self.t,
                        partial_signatures.len()
                    ),
                    None,
                ));
            }
            
            // Ensure we have unique indices
            let mut indices = HashSet::new();
            for sig in partial_signatures {
                if !indices.insert(sig.index) {
                    return Err(AevorError::crypto(
                        "Duplicate signature index".into(),
                        format!("Duplicate index: {}", sig.index),
                        None,
                    ));
                }
                
                if sig.index == 0 || sig.index > self.n {
                    return Err(AevorError::crypto(
                        "Invalid signature index".into(),
                        format!("Index must be between 1 and {}, got {}", self.n, sig.index),
                        None,
                    ));
                }
            }
            
            // We'll use the first t partial signatures
            let used_signatures = &partial_signatures[0..self.t];
            
            // Convert signatures to G2 points
            let mut sig_points = Vec::with_capacity(self.t);
            let mut participant_indices = Vec::with_capacity(self.t);
            
            for sig in used_signatures {
                let point = g2_from_bytes(&sig.signature.bytes)?;
                sig_points.push(point);
                participant_indices.push(sig.index);
            }
            
            // Compute Lagrange coefficients
            let mut lagrange_coefficients = Vec::with_capacity(self.t);
            
            for i in 0..self.t {
                let mut numerator = Scalar::one();
                let mut denominator = Scalar::one();
                
                let i_idx = used_signatures[i].index as u64;
                
                for j in 0..self.t {
                    if i == j {
                        continue;
                    }
                    
                    let j_idx = used_signatures[j].index as u64;
                    
                    numerator *= Scalar::from(j_idx);
                    denominator *= Scalar::from(j_idx - i_idx);
                }
                
                // lambda_i = numerator / denominator
                let lambda_i = numerator * denominator.invert().unwrap_or(Scalar::zero());
                lagrange_coefficients.push(lambda_i);
            }
            
            // Reconstruct the signature
            let mut reconstructed = G2Projective::identity();
            
            for i in 0..self.t {
                reconstructed += sig_points[i] * lagrange_coefficients[i];
            }
            
            Ok(BlsThresholdSignature {
                signature: BlsSignature {
                    bytes: g2_to_bytes(&reconstructed),
                },
                participants: participant_indices,
            })
        }
        
        /// Verifies a reconstructed signature
        pub fn verify_signature(&self, signature: &BlsThresholdSignature, message: &[u8]) -> Result<bool> {
            let master_pk = self.master_public_key();
            signature.signature.verify(&master_pk, message)
        }
    }
    
    impl BlsThresholdShare {
        /// Signs a message with this share
        pub fn sign(&self, message: &[u8]) -> Result<BlsPartialSignature> {
            let signature = self.private_key.sign(message)?;
            
            Ok(BlsPartialSignature {
                index: self.index,
                signature,
            })
        }
        
        /// Verifies that this share is valid for the given public verification vector
        pub fn verify(&self, verification_vector: &[BlsPublicKey]) -> Result<bool> {
            if verification_vector.is_empty() {
                return Err(AevorError::crypto(
                    "Empty verification vector".into(),
                    "Cannot verify share with empty verification vector".into(),
                    None,
                ));
            }
            
            // The public key should be g * f(i) where f is the polynomial
            // We can verify this by checking that public_key = Σ verification_vector[j] * i^j
            
            let x = Scalar::from(self.index as u64);
            let mut expected_public_key = G1Projective::identity();
            
            let mut x_pow = Scalar::one();
            for vv_point in verification_vector {
                let point = g1_from_bytes(&vv_point.bytes)?;
                expected_public_key += point * x_pow;
                x_pow *= x;
            }
            
            let actual_public_key = g1_from_bytes(&self.public_key.bytes)?;
            
            Ok(expected_public_key == actual_public_key)
        }
    }
    
    impl BlsThresholdSignature {
        /// Verifies this signature against a public key
        pub fn verify(&self, public_key: &BlsPublicKey, message: &[u8]) -> Result<bool> {
            self.signature.verify(public_key, message)
        }
    }
}

/// BLS signature aggregation utilities specifically designed for the Security Level Accelerator
pub mod security_accelerator {
    use super::*;
    use crate::core::transaction::security::SecurityLevel;
    
    /// A BLS signature bundle for the Security Level Accelerator
    #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SecurityLevelSignature {
        /// The aggregated signature
        pub signature: BlsAggregateSignature,
        
        /// The security level this signature represents
        pub security_level: SecurityLevel,
        
        /// The total stake represented by this signature
        pub total_stake: u64,
        
        /// The percentage of total validator stake represented
        pub stake_percentage: u8,
        
        /// Timestamp when this security level was reached
        pub timestamp: u64,
    }
    
    impl SecurityLevelSignature {
        /// Creates a new security level signature
        pub fn new(
            signature: BlsAggregateSignature,
            security_level: SecurityLevel,
            total_stake: u64,
            stake_percentage: u8,
        ) -> Self {
            Self {
                signature,
                security_level,
                total_stake,
                stake_percentage,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            }
        }
        
        /// Verifies this signature against a message
        pub fn verify(&self, message: &[u8]) -> Result<bool> {
            self.signature.verify_single_message(message)
        }
        
        /// Gets the number of validators that signed
        pub fn validator_count(&self) -> usize {
            self.signature.signer_count()
        }
        
        /// Checks if this signature meets the minimum requirements for a security level
        pub fn meets_security_level(&self, required_level: SecurityLevel) -> bool {
            self.security_level >= required_level
        }
        
        /// Gets the time it took to reach this security level
        pub fn time_to_reach(&self) -> u64 {
            let now = chrono::Utc::now().timestamp_millis() as u64;
            now - self.timestamp
        }
    }
    
    /// A signature collector for accumulating signatures to reach a target security level
    pub struct SecurityLevelSignatureCollector {
        /// Target message being signed
        message: Vec<u8>,
        
        /// Received signatures with their validator information
        signatures: HashMap<Vec<u8>, (BlsSignature, BlsPublicKey, u64)>, // validator_id -> (signature, public_key, stake)
        
        /// Total stake in the validator set
        total_stake: u64,
        
        /// Current security level
        current_level: SecurityLevel,
        
        /// Start time
        start_time: u64,
        
        /// Security level thresholds (percentage of stake needed)
        level_thresholds: HashMap<SecurityLevel, u8>,
    }
    
    impl SecurityLevelSignatureCollector {
        /// Creates a new signature collector for a given message
        pub fn new(message: Vec<u8>, total_stake: u64) -> Self {
            // Default thresholds for security levels
            let mut level_thresholds = HashMap::new();
            level_thresholds.insert(SecurityLevel::Minimal, 1); // 1% for Minimal
            level_thresholds.insert(SecurityLevel::Basic, 15);  // 15% for Basic
            level_thresholds.insert(SecurityLevel::Strong, 34); // 34% for Strong
            level_thresholds.insert(SecurityLevel::Full, 67);   // 67% for Full
            
            Self {
                message,
                signatures: HashMap::new(),
                total_stake,
                current_level: SecurityLevel::Minimal,
                start_time: chrono::Utc::now().timestamp_millis() as u64,
                level_thresholds,
            }
        }
        
        /// Adds a validator signature
        pub fn add_signature(
            &mut self,
            validator_id: Vec<u8>,
            signature: BlsSignature,
            public_key: BlsPublicKey,
            stake: u64,
        ) -> Result<Option<SecurityLevelSignature>> {
            // Skip if already added
            if self.signatures.contains_key(&validator_id) {
                return Ok(None);
            }
            
            // Verify the signature
            if !signature.verify(&public_key, &self.message)? {
                return Err(AevorError::crypto(
                    "Invalid signature".into(),
                    "Signature verification failed".into(),
                    None,
                ));
            }
            
            // Add the signature
            self.signatures.insert(validator_id, (signature, public_key, stake));
            
            // Check if we've reached a new security level
            self.update_security_level()
        }
        
        /// Updates the current security level based on collected signatures
        fn update_security_level(&mut self) -> Result<Option<SecurityLevelSignature>> {
            // Calculate total stake represented by signatures
            let mut collected_stake: u64 = 0;
            for (_, (_, _, stake)) in &self.signatures {
                collected_stake += *stake;
            }
            
            // Calculate stake percentage
            let stake_percentage = if self.total_stake == 0 {
                0
            } else {
                ((collected_stake as f64 / self.total_stake as f64) * 100.0) as u8
            };
            
            // Determine the highest security level reached
            let mut new_level = self.current_level;
            for level in [
                SecurityLevel::Full,
                SecurityLevel::Strong,
                SecurityLevel::Basic,
                SecurityLevel::Minimal,
            ]
            .iter()
            {
                let threshold = self.level_thresholds.get(level).cloned().unwrap_or(0);
                if stake_percentage >= threshold && *level > self.current_level {
                    new_level = *level;
                    break;
                }
            }
            
            // If security level has improved, create a new security level signature
            if new_level > self.current_level {
                self.current_level = new_level;
                
                // Aggregate signatures
                let signatures: Vec<_> = self.signatures.values().map(|(sig, _, _)| sig.clone()).collect();
                let public_keys: Vec<_> = self.signatures.values().map(|(_, pk, _)| pk.clone()).collect();
                
                let aggregated_signature = BlsSignature::aggregate(&signatures)?;
                let bls_aggregate = BlsAggregateSignature {
                    bytes: aggregated_signature.bytes,
                    public_keys,
                    metadata: HashMap::new(),
                };
                
                let security_sig = SecurityLevelSignature::new(
                    bls_aggregate,
                    new_level,
                    collected_stake,
                    stake_percentage,
                );
                
                return Ok(Some(security_sig));
            }
            
            Ok(None)
        }
        
        /// Gets the current security level
        pub fn current_level(&self) -> SecurityLevel {
            self.current_level
        }
        
        /// Gets the current stake percentage
        pub fn stake_percentage(&self) -> u8 {
            let collected_stake: u64 = self.signatures.values().map(|(_, _, stake)| stake).sum();
            
            if self.total_stake == 0 {
                0
            } else {
                ((collected_stake as f64 / self.total_stake as f64) * 100.0) as u8
            }
        }
        
        /// Gets the number of validators that have signed
        pub fn validator_count(&self) -> usize {
            self.signatures.len()
        }
        
        /// Sets custom thresholds for security levels
        pub fn set_thresholds(&mut self, thresholds: HashMap<SecurityLevel, u8>) {
            self.level_thresholds = thresholds;
            
            // Re-evaluate current security level with new thresholds
            if let Ok(Some(_)) = self.update_security_level() {
                // Security level updated with new thresholds
            }
        }
        
        /// Gets the aggregate signature at the current security level
        pub fn current_aggregate_signature(&self) -> Result<SecurityLevelSignature> {
            if self.signatures.is_empty() {
                return Err(AevorError::crypto(
                    "No signatures".into(),
                    "Cannot create aggregate signature with no signatures".into(),
                    None,
                ));
            }
            
            // Aggregate signatures
            let signatures: Vec<_> = self.signatures.values().map(|(sig, _, _)| sig.clone()).collect();
            let public_keys: Vec<_> = self.signatures.values().map(|(_, pk, _)| pk.clone()).collect();
            
            let collected_stake: u64 = self.signatures.values().map(|(_, _, stake)| *stake).sum();
            let stake_percentage = if self.total_stake == 0 {
                0
            } else {
                ((collected_stake as f64 / self.total_stake as f64) * 100.0) as u8
            };
            
            let aggregated_signature = BlsSignature::aggregate(&signatures)?;
            let bls_aggregate = BlsAggregateSignature {
                bytes: aggregated_signature.bytes,
                public_keys,
                metadata: HashMap::new(),
            };
            
            Ok(SecurityLevelSignature::new(
                bls_aggregate,
                self.current_level,
                collected_stake,
                stake_percentage,
            ))
        }
        
        /// Checks if a specific security level has been reached
        pub fn has_reached_level(&self, level: SecurityLevel) -> bool {
            self.current_level >= level
        }
        
        /// Gets the elapsed time since collection started
        pub fn elapsed_time(&self) -> u64 {
            let now = chrono::Utc::now().timestamp_millis() as u64;
            now - self.start_time
        }
        
        /// Gets the message being signed
        pub fn message(&self) -> &[u8] {
            &self.message
        }
    }
    
    /// A verification context for validating security level signatures
    pub struct SecurityLevelVerifier {
        /// Known validators and their public keys and stakes
        validators: HashMap<Vec<u8>, (BlsPublicKey, u64)>, // validator_id -> (public_key, stake)
        
        /// Total stake in the validator set
        total_stake: u64,
        
        /// Security level thresholds (percentage of stake needed)
        level_thresholds: HashMap<SecurityLevel, u8>,
    }
    
    impl SecurityLevelVerifier {
        /// Creates a new security level verifier
        pub fn new() -> Self {
            // Default thresholds for security levels
            let mut level_thresholds = HashMap::new();
            level_thresholds.insert(SecurityLevel::Minimal, 1); // 1% for Minimal
            level_thresholds.insert(SecurityLevel::Basic, 15);  // 15% for Basic
            level_thresholds.insert(SecurityLevel::Strong, 34); // 34% for Strong
            level_thresholds.insert(SecurityLevel::Full, 67);   // 67% for Full
            
            Self {
                validators: HashMap::new(),
                total_stake: 0,
                level_thresholds,
            }
        }
        
        /// Adds a validator to the verifier
        pub fn add_validator(&mut self, id: Vec<u8>, public_key: BlsPublicKey, stake: u64) {
            self.validators.insert(id, (public_key, stake));
            self.total_stake += stake;
        }
        
        /// Removes a validator from the verifier
        pub fn remove_validator(&mut self, id: &[u8]) {
            if let Some((_, stake)) = self.validators.remove(id) {
                self.total_stake -= stake;
            }
        }
        
        /// Sets custom thresholds for security levels
        pub fn set_thresholds(&mut self, thresholds: HashMap<SecurityLevel, u8>) {
            self.level_thresholds = thresholds;
        }
        
        /// Verifies a security level signature
        pub fn verify_signature(
            &self,
            signature: &SecurityLevelSignature,
            message: &[u8],
        ) -> Result<bool> {
            // Verify the BLS signature
            let valid_signature = signature.signature.verify_single_message(message)?;
            if !valid_signature {
                return Ok(false);
            }
            
            // Verify the security level
            let mut collected_stake: u64 = 0;
            let mut validator_count = 0;
            
            // Find the validators in our known set
            for public_key in &signature.signature.public_keys {
                let mut found = false;
                
                for (_, (val_pk, stake)) in &self.validators {
                    if val_pk == public_key {
                        collected_stake += stake;
                        validator_count += 1;
                        found = true;
                        break;
                    }
                }
                
                if !found {
                    return Err(AevorError::crypto(
                        "Unknown validator".into(),
                        "Signature contains unknown validator".into(),
                        None,
                    ));
                }
            }
            
            // Calculate stake percentage
            let stake_percentage = if self.total_stake == 0 {
                0
            } else {
                ((collected_stake as f64 / self.total_stake as f64) * 100.0) as u8
            };
            
            // Verify the security level based on stake percentage
            let threshold = self.level_thresholds.get(&signature.security_level).cloned().unwrap_or(0);
            
            if stake_percentage < threshold {
                return Ok(false);
            }
            
            // Verify minimum validator count for each security level
            match signature.security_level {
                SecurityLevel::Minimal => {
                    if validator_count < 1 {
                        return Ok(false);
                    }
                }
                SecurityLevel::Basic => {
                    if validator_count < 3 {
                        return Ok(false);
                    }
                }
                SecurityLevel::Strong => {
                    if validator_count < 5 {
                        return Ok(false);
                    }
                }
                SecurityLevel::Full => {
                    if validator_count < 7 {
                        return Ok(false);
                    }
                }
            }
            
            Ok(true)
        }
        
        /// Gets the total stake
        pub fn total_stake(&self) -> u64 {
            self.total_stake
        }
        
        /// Gets the number of validators
        pub fn validator_count(&self) -> usize {
            self.validators.len()
        }
        
        /// Gets the threshold for a security level
        pub fn threshold_for_level(&self, level: SecurityLevel) -> u8 {
            self.level_thresholds.get(&level).cloned().unwrap_or(0)
        }
        
        /// Checks if a validator is known
        pub fn is_validator(&self, id: &[u8]) -> bool {
            self.validators.contains_key(id)
        }
        
        /// Gets a validator's public key and stake
        pub fn get_validator(&self, id: &[u8]) -> Option<(&BlsPublicKey, u64)> {
            self.validators.get(id).map(|(pk, stake)| (pk, *stake))
        }
    }
}

impl fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsPublicKey({})", hex::encode(&self.bytes))
    }
}

impl fmt::Debug for BlsPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsPrivateKey(...)")
    }
}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsSignature({})", hex::encode(&self.bytes))
    }
}

impl fmt::Debug for BlsAggregateSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlsAggregateSignature")
            .field("signature", &hex::encode(&self.bytes))
            .field("signers", &self.public_keys.len())
            .field("metadata_keys", &self.metadata.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let keypair = BlsKeyPair::random();
        let public_key = keypair.public_key();
        let private_key = keypair.private_key();
        
        // Public key should be G1 point (48 bytes compressed)
        assert_eq!(public_key.bytes.len(), 48);
        
        // Private key should be scalar (32 bytes)
        assert_eq!(private_key.bytes.len(), 32);
        
        // Recreate key pair from private key
        let keypair2 = BlsKeyPair::from_private_key(&private_key).unwrap();
        let public_key2 = keypair2.public_key();
        
        // Public keys should match
        assert_eq!(public_key.bytes, public_key2.bytes);
    }
    
    #[test]
    fn test_signature_verification() {
        let keypair = BlsKeyPair::random();
        let message = b"Hello, world!";
        
        // Sign the message
        let signature = keypair.sign(message);
        
        // Verify the signature
        let public_key = keypair.public_key();
        let result = signature.verify(&public_key, message).unwrap();
        
        assert!(result);
        
        // Verify with a different message should fail
        let different_message = b"Different message";
        let result = signature.verify(&public_key, different_message).unwrap();
        
        assert!(!result);
        
        // Verify with a different public key should fail
        let different_keypair = BlsKeyPair::random();
        let different_public_key = different_keypair.public_key();
        let result = signature.verify(&different_public_key, message).unwrap();
        
        assert!(!result);
    }
    
    #[test]
    fn test_signature_aggregation() {
        let keypair1 = BlsKeyPair::random();
        let keypair2 = BlsKeyPair::random();
        let keypair3 = BlsKeyPair::random();
        
        let message = b"Hello, world!";
        
        // Sign the message with all key pairs
        let signature1 = keypair1.sign(message);
        let signature2 = keypair2.sign(message);
        let signature3 = keypair3.sign(message);
        
        // Aggregate the signatures
        let signatures = vec![signature1.clone(), signature2.clone(), signature3.clone()];
        let aggregate = BlsSignature::aggregate(&signatures).unwrap();
        
        // Aggregate the public keys
        let public_keys = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];
        let aggregate_public_key = BlsPublicKey::aggregate(&public_keys).unwrap();
        
        // Verify the aggregate signature with the aggregate public key
        let result = aggregate.verify(&aggregate_public_key, message).unwrap();
        assert!(result);
        
        // Create an aggregate signature object
        let agg_sig = aggregate.create_aggregate_signature(public_keys);
        
        // Verify against the same message
        let result = agg_sig.verify_single_message(message).unwrap();
        assert!(result);
    }
    
    #[test]
    fn test_threshold_signatures() {
        use super::threshold::*;
        
        // Create a 3-of-5 threshold scheme
        let scheme = BlsThresholdScheme::new(5, 3).unwrap();
        
        // Generate shares
        let shares = scheme.generate_shares();
        assert_eq!(shares.len(), 5);
        
        // Get the master public key
        let master_pk = scheme.master_public_key();
        
        // Create partial signatures
        let message = b"Hello, threshold world!";
        let mut partial_sigs = Vec::new();
        
        for i in 0..3 {
            let partial = shares[i].sign(message).unwrap();
            partial_sigs.push(partial);
        }
        
        // Reconstruct the signature
        let reconstructed = scheme.reconstruct_signature(&partial_sigs).unwrap();
        
        // Verify the reconstructed signature
        let result = scheme.verify_signature(&reconstructed, message).unwrap();
        assert!(result);
        
        // Also verify with the master public key
        let result = reconstructed.signature.verify(&master_pk, message).unwrap();
        assert!(result);
    }
    
    #[test]
    fn test_security_accelerator() {
        use super::security_accelerator::*;
        use crate::core::transaction::security::SecurityLevel;
        
        let message = b"Test message for security accelerator".to_vec();
        
        // Create 10 validators with different stakes
        let mut validators = Vec::new();
        let mut total_stake = 0;
        
        for i in 0..10 {
            let keypair = BlsKeyPair::random();
            let stake = (i + 1) * 10; // Stakes: 10, 20, 30, ..., 100
            validators.push((keypair, stake));
            total_stake += stake;
        }
        
        // Create a signature collector
        let mut collector = SecurityLevelSignatureCollector::new(message.clone(), total_stake);
        
        // Add signatures one by one and track security level progression
        let mut reached_levels = Vec::new();
        
        for (i, (keypair, stake)) in validators.iter().enumerate() {
            let signature = keypair.sign(&message);
            let public_key = keypair.public_key();
            let validator_id = vec![i as u8];
            
            let result = collector.add_signature(
                validator_id,
                signature,
                public_key,
                *stake,
            ).unwrap();
            
            if let Some(security_sig) = result {
                reached_levels.push(security_sig.security_level);
            }
        }
        
        // We should have progressed through security levels
        assert!(!reached_levels.is_empty());
        assert_eq!(collector.current_level(), SecurityLevel::Full);
        
        // Create a verifier
        let mut verifier = SecurityLevelVerifier::new();
        
        // Add validators to the verifier
        for (i, (keypair, stake)) in validators.iter().enumerate() {
            let public_key = keypair.public_key();
            let validator_id = vec![i as u8];
            verifier.add_validator(validator_id, public_key, *stake);
        }
        
        // Get the current aggregate signature
        let security_sig = collector.current_aggregate_signature().unwrap();
        
        // Verify it
        let result = verifier.verify_signature(&security_sig, &message).unwrap();
        assert!(result);
    }
}
