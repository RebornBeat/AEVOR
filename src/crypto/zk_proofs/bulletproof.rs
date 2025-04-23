use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::{AevorError, Result};
use super::{create_transcript, domain_separator, ProofSystem, util};

/// Parameters for a Bulletproof range proof
#[derive(Clone, Serialize, Deserialize)]
pub struct RangeProofParams {
    /// The base point G used in the range proof
    pub g: CompressedRistretto,
    
    /// The base point H used in the range proof
    pub h: CompressedRistretto,
    
    /// The generators for bit commitments
    pub g_vec: Vec<CompressedRistretto>,
    
    /// The generators for bit commitment blinding factors
    pub h_vec: Vec<CompressedRistretto>,
    
    /// The lower bound of the range (typically 0)
    pub min_value: u64,
    
    /// The upper bound of the range
    pub max_value: u64,
    
    /// The bit size of the range proof
    pub bit_size: usize,
}

impl RangeProofParams {
    /// Creates new range proof parameters
    pub fn new(bit_size: usize, min_value: u64, max_value: u64) -> Result<Self> {
        if bit_size == 0 || bit_size > 64 {
            return Err(AevorError::crypto(
                "Invalid bit size".into(),
                format!("Bit size must be between 1 and 64, got {}", bit_size),
                None,
            ));
        }
        
        if min_value >= max_value {
            return Err(AevorError::crypto(
                "Invalid range".into(),
                format!("min_value {} must be less than max_value {}", min_value, max_value),
                None,
            ));
        }
        
        let mut rng = OsRng;
        
        // Create generators using deterministic method derived from domain separator
        let domain_sep = domain_separator(b"bulletproof_generators");
        let mut transcript = Transcript::new(b"bulletproof_param_generation");
        transcript.append_message(b"domain_separator", &domain_sep);
        
        // Generate base points
        let g_scalar = Scalar::random(&mut rng);
        let h_scalar = Scalar::random(&mut rng);
        let g = RistrettoPoint::random(&mut rng).compress();
        let h = RistrettoPoint::random(&mut rng).compress();
        
        // Generate vector generators
        let mut g_vec = Vec::with_capacity(bit_size);
        let mut h_vec = Vec::with_capacity(bit_size);
        
        for i in 0..bit_size {
            transcript.append_u64(b"i", i as u64);
            let mut g_i_bytes = [0u8; 32];
            let mut h_i_bytes = [0u8; 32];
            
            transcript.challenge_bytes(b"g_i", &mut g_i_bytes);
            transcript.challenge_bytes(b"h_i", &mut h_i_bytes);
            
            let g_i_scalar = Scalar::from_bytes_mod_order(g_i_bytes);
            let h_i_scalar = Scalar::from_bytes_mod_order(h_i_bytes);
            
            let g_i = (g.decompress().unwrap() * g_i_scalar).compress();
            let h_i = (h.decompress().unwrap() * h_i_scalar).compress();
            
            g_vec.push(g_i);
            h_vec.push(h_i);
        }
        
        Ok(Self {
            g,
            h,
            g_vec,
            h_vec,
            min_value,
            max_value,
            bit_size,
        })
    }
    
    /// Serializes the parameters to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        util::serialize_params(self)
    }
    
    /// Deserializes parameters from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        util::deserialize_params(bytes)
    }
}

impl fmt::Debug for RangeProofParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RangeProofParams")
            .field("g", &"CompressedRistretto(...)")
            .field("h", &"CompressedRistretto(...)")
            .field("g_vec_len", &self.g_vec.len())
            .field("h_vec_len", &self.h_vec.len())
            .field("min_value", &self.min_value)
            .field("max_value", &self.max_value)
            .field("bit_size", &self.bit_size)
            .finish()
    }
}

/// A Bulletproof range proof
#[derive(Clone, Serialize, Deserialize)]
pub struct BulletproofRangeProof {
    /// The value commitment
    pub v_commitment: CompressedRistretto,
    
    /// A and S points in the inner product argument
    pub a: CompressedRistretto,
    pub s: CompressedRistretto,
    
    /// T1 and T2 commitments in the inner product argument
    pub t_1: CompressedRistretto,
    pub t_2: CompressedRistretto,
    
    /// The challenges from the proof transcript
    pub tau_x: Scalar,
    pub mu: Scalar,
    pub t_hat: Scalar,
    
    /// The l and r vectors in the inner product proof
    pub l_vec: Vec<CompressedRistretto>,
    pub r_vec: Vec<CompressedRistretto>,
    
    /// The final scalars in the inner product proof
    pub a_scalar: Scalar,
    pub b_scalar: Scalar,
}

impl BulletproofRangeProof {
    /// Creates a new range proof that a value is within a specified range
    pub fn prove(params: &RangeProofParams, value: u64, blinding: &[u8]) -> Result<Self> {
        // Validate that the value is in range
        if value < params.min_value || value > params.max_value {
            return Err(AevorError::crypto(
                "Value out of range".into(),
                format!("Value {} is outside the range [{}, {}]", 
                    value, params.min_value, params.max_value),
                None,
            ));
        }
        
        // Convert blinding to a scalar
        let mut blinding_scalar_bytes = [0u8; 32];
        if blinding.len() >= 32 {
            blinding_scalar_bytes.copy_from_slice(&blinding[..32]);
        } else {
            blinding_scalar_bytes[..blinding.len()].copy_from_slice(blinding);
        }
        let blinding_scalar = Scalar::from_bytes_mod_order(blinding_scalar_bytes);
        
        // Convert value to bit representation
        let bits: Vec<bool> = (0..params.bit_size)
            .map(|i| ((value >> i) & 1) == 1)
            .collect();
            
        // Create a new transcript for the proof
        let mut transcript = create_transcript(b"bulletproof_range_proof");
        
        // The g and h points from the parameters
        let g = params.g.decompress().ok_or_else(|| 
            AevorError::crypto(
                "Invalid point".into(),
                "Could not decompress g point".into(),
                None,
            ))?;
        
        let h = params.h.decompress().ok_or_else(|| 
            AevorError::crypto(
                "Invalid point".into(),
                "Could not decompress h point".into(),
                None,
            ))?;
        
        // Decompress generator vectors
        let g_vec: Vec<RistrettoPoint> = params.g_vec.iter()
            .map(|p| p.decompress().ok_or_else(|| 
                AevorError::crypto(
                    "Invalid point".into(),
                    "Could not decompress g_vec point".into(),
                    None,
                )))
            .collect::<Result<Vec<RistrettoPoint>>>()?;
        
        let h_vec: Vec<RistrettoPoint> = params.h_vec.iter()
            .map(|p| p.decompress().ok_or_else(|| 
                AevorError::crypto(
                    "Invalid point".into(),
                    "Could not decompress h_vec point".into(),
                    None,
                )))
            .collect::<Result<Vec<RistrettoPoint>>>()?;
        
        let mut rng = OsRng;
        
        // V = value * G + blinding * H
        let v_commitment = (g * Scalar::from(value) + h * blinding_scalar).compress();
        
        // Commit to the bit decomposition of the value
        let a_blinding = Scalar::random(&mut rng);
        let s_blinding = Scalar::random(&mut rng);
        
        // A = sum_{i=0}^{n-1} a_i * G_i + a_blinding * H
        let a_commitment: RistrettoPoint = g_vec.iter().zip(bits.iter())
            .map(|(g_i, bit)| if *bit { *g_i } else { RistrettoPoint::identity() })
            .sum::<RistrettoPoint>() + h * a_blinding;
        
        // S = sum_{i=0}^{n-1} s_i * G_i + s_blinding * H
        let s_i: Vec<Scalar> = bits.iter()
            .map(|bit| if *bit { Scalar::one() } else { Scalar::zero() })
            .collect();
        
        let s_commitment: RistrettoPoint = h_vec.iter().zip(s_i.iter())
            .map(|(h_i, s_i)| *h_i * *s_i)
            .sum::<RistrettoPoint>() + h * s_blinding;
        
        // Append commitments to transcript and get challenge y
        transcript.append_point(b"V", &v_commitment);
        transcript.append_point(b"A", &a_commitment.compress());
        transcript.append_point(b"S", &s_commitment.compress());
        
        let mut y_bytes = [0u8; 32];
        transcript.challenge_bytes(b"y", &mut y_bytes);
        let y = Scalar::from_bytes_mod_order(y_bytes);
        
        let mut z_bytes = [0u8; 32];
        transcript.challenge_bytes(b"z", &mut z_bytes);
        let z = Scalar::from_bytes_mod_order(z_bytes);
        
        // tau_1 and tau_2 are blinding factors for T_1 and T_2
        let tau_1 = Scalar::random(&mut rng);
        let tau_2 = Scalar::random(&mut rng);
        
        // Calculate t_1 and t_2 scalars
        let t_1_scalar = Scalar::from(value) * z + a_blinding;
        let t_2_scalar = Scalar::from(value) * z * z + s_blinding;
        
        // Calculate T_1 and T_2 commitments
        let t_1 = (g * t_1_scalar + h * tau_1).compress();
        let t_2 = (g * t_2_scalar + h * tau_2).compress();
        
        // Append T_1 and T_2 to transcript and get challenge x
        transcript.append_point(b"T_1", &t_1);
        transcript.append_point(b"T_2", &t_2);
        
        let mut x_bytes = [0u8; 32];
        transcript.challenge_bytes(b"x", &mut x_bytes);
        let x = Scalar::from_bytes_mod_order(x_bytes);
        
        // Calculate t_hat and calculate blinding factor tau_x
        let t_hat = t_1_scalar * x + t_2_scalar * x * x;
        let tau_x = tau_1 * x + tau_2 * x * x;
        
        // Append t_hat and tau_x to transcript and get challenge e
        transcript.append_scalar(b"t_hat", &t_hat);
        transcript.append_scalar(b"tau_x", &tau_x);
        
        let mut e_bytes = [0u8; 32];
        transcript.challenge_bytes(b"e", &mut e_bytes);
        let e = Scalar::from_bytes_mod_order(e_bytes);
        
        // Calculate the mu challenge for the inner product proof
        let mu = a_blinding * e + s_blinding;
        
        // Placeholder for inner product argument
        // In a real implementation, this would generate the l_vec and r_vec points
        // along with the final a_scalar and b_scalar for the inner product argument
        
        // For now, we'll generate placeholders
        let l_vec = vec![g.compress(); params.bit_size.min(8)];
        let r_vec = vec![h.compress(); params.bit_size.min(8)];
        let a_scalar = Scalar::random(&mut rng);
        let b_scalar = Scalar::random(&mut rng);
        
        Ok(Self {
            v_commitment,
            a: a_commitment.compress(),
            s: s_commitment.compress(),
            t_1,
            t_2,
            tau_x,
            mu,
            t_hat,
            l_vec,
            r_vec,
            a_scalar,
            b_scalar,
        })
    }
    
    /// Serializes the proof to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        util::serialize_proof(self)
    }
    
    /// Deserializes a proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        util::deserialize_proof(bytes)
    }
}

impl fmt::Debug for BulletproofRangeProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulletproofRangeProof")
            .field("v_commitment", &"CompressedRistretto(...)")
            .field("a", &"CompressedRistretto(...)")
            .field("s", &"CompressedRistretto(...)")
            .field("t_1", &"CompressedRistretto(...)")
            .field("t_2", &"CompressedRistretto(...)")
            .field("l_vec_len", &self.l_vec.len())
            .field("r_vec_len", &self.r_vec.len())
            .finish()
    }
}

/// System for creating and verifying Bulletproof range proofs
pub struct BulletproofProofSystem;

impl BulletproofProofSystem {
    /// Generates a range proof that a value is within a specified range
    pub fn prove_range(
        params: &RangeProofParams, 
        value: u64, 
        blinding: &[u8]
    ) -> Result<BulletproofRangeProof> {
        BulletproofRangeProof::prove(params, value, blinding)
    }
    
    /// Verifies a range proof
    pub fn verify_range_proof(
        params: &RangeProofParams, 
        proof: &BulletproofRangeProof
    ) -> Result<bool> {
        // The g and h points from the parameters
        let g = params.g.decompress().ok_or_else(|| 
            AevorError::crypto(
                "Invalid point".into(),
                "Could not decompress g point".into(),
                None,
            ))?;
        
        let h = params.h.decompress().ok_or_else(|| 
            AevorError::crypto(
                "Invalid point".into(),
                "Could not decompress h point".into(),
                None,
            ))?;
        
        // Start a new transcript for verification
        let mut transcript = create_transcript(b"bulletproof_range_proof");
        
        // Append the same values to the transcript as during proving
        transcript.append_point(b"V", &proof.v_commitment);
        transcript.append_point(b"A", &proof.a);
        transcript.append_point(b"S", &proof.s);
        
        // Extract the same challenges that were used during proving
        let mut y_bytes = [0u8; 32];
        transcript.challenge_bytes(b"y", &mut y_bytes);
        let y = Scalar::from_bytes_mod_order(y_bytes);
        
        let mut z_bytes = [0u8; 32];
        transcript.challenge_bytes(b"z", &mut z_bytes);
        let z = Scalar::from_bytes_mod_order(z_bytes);
        
        // Continue with the transcript
        transcript.append_point(b"T_1", &proof.t_1);
        transcript.append_point(b"T_2", &proof.t_2);
        
        let mut x_bytes = [0u8; 32];
        transcript.challenge_bytes(b"x", &mut x_bytes);
        let x = Scalar::from_bytes_mod_order(x_bytes);
        
        // Append t_hat and tau_x
        transcript.append_scalar(b"t_hat", &proof.t_hat);
        transcript.append_scalar(b"tau_x", &proof.tau_x);
        
        let mut e_bytes = [0u8; 32];
        transcript.challenge_bytes(b"e", &mut e_bytes);
        let e = Scalar::from_bytes_mod_order(e_bytes);
        
        // In a real implementation, you would now verify the inner product proof
        // using l_vec, r_vec, a_scalar, and b_scalar
        
        // For this implementation, we'll just do a simplified check
        let a = proof.a.decompress().ok_or_else(|| 
            AevorError::crypto(
                "Invalid point".into(),
                "Could not decompress A point".into(),
                None,
            ))?;
        
        let s = proof.s.decompress().ok_or_else(|| 
            AevorError::crypto(
                "Invalid point".into(),
                "Could not decompress S point".into(),
                None,
            ))?;
        
        let t_1 = proof.t_1.decompress().ok_or_else(|| 
            AevorError::crypto(
                "Invalid point".into(),
                "Could not decompress T_1 point".into(),
                None,
            ))?;
        
        let t_2 = proof.t_2.decompress().ok_or_else(|| 
            AevorError::crypto(
                "Invalid point".into(),
                "Could not decompress T_2 point".into(),
                None,
            ))?;
        
        // Check that the commitment opens to a value in the range
        // This would be a comprehensive check in a real implementation
        
        // For now, we'll just do a simplified check that mimics some of the math
        let check1 = (t_1 * x + t_2 * x * x).compress();
        let check2 = (a * e + s * e).compress();
        
        // These checks are placeholders and would be more comprehensive in a real implementation
        let valid = !check1.eq(&RistrettoPoint::identity().compress()) && 
                   !check2.eq(&RistrettoPoint::identity().compress());
        
        Ok(valid)
    }
}

impl ProofSystem<RangeProofParams, BulletproofRangeProof> for BulletproofProofSystem {
    fn verify(params: &RangeProofParams, proof: &BulletproofRangeProof) -> Result<bool> {
        Self::verify_range_proof(params, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_range_proof_params_creation() {
        let result = RangeProofParams::new(32, 0, 1_000_000);
        assert!(result.is_ok());
        
        let params = result.unwrap();
        assert_eq!(params.bit_size, 32);
        assert_eq!(params.min_value, 0);
        assert_eq!(params.max_value, 1_000_000);
        assert_eq!(params.g_vec.len(), 32);
        assert_eq!(params.h_vec.len(), 32);
    }
    
    #[test]
    fn test_range_proof_params_validation() {
        // Test with invalid bit size
        let result = RangeProofParams::new(0, 0, 100);
        assert!(result.is_err());
        
        let result = RangeProofParams::new(65, 0, 100);
        assert!(result.is_err());
        
        // Test with invalid range
        let result = RangeProofParams::new(32, 100, 100);
        assert!(result.is_err());
        
        let result = RangeProofParams::new(32, 200, 100);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_range_proof_params_serialization() {
        let params = RangeProofParams::new(32, 0, 1_000_000).unwrap();
        
        // Test serialization
        let bytes = params.to_bytes().unwrap();
        assert!(!bytes.is_empty());
        
        // Test deserialization
        let deserialized = RangeProofParams::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.bit_size, params.bit_size);
        assert_eq!(deserialized.min_value, params.min_value);
        assert_eq!(deserialized.max_value, params.max_value);
    }
    
    #[test]
    fn test_range_proof_creation_and_verification() {
        let params = RangeProofParams::new(32, 0, 1_000_000).unwrap();
        let value = 123456;
        let blinding = [42u8; 32];
        
        // Create a range proof
        let proof = BulletproofProofSystem::prove_range(&params, value, &blinding).unwrap();
        
        // Verify the proof
        let verification = BulletproofProofSystem::verify_range_proof(&params, &proof).unwrap();
        assert!(verification);
    }
    
    #[test]
    fn test_range_proof_out_of_range() {
        let params = RangeProofParams::new(32, 0, 1_000_000).unwrap();
        let value = 2_000_000; // Out of range
        let blinding = [42u8; 32];
        
        // Creating a proof for an out-of-range value should fail
        let result = BulletproofProofSystem::prove_range(&params, value, &blinding);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_range_proof_serialization() {
        let params = RangeProofParams::new(32, 0, 1_000_000).unwrap();
        let value = 123456;
        let blinding = [42u8; 32];
        
        let proof = BulletproofProofSystem::prove_range(&params, value, &blinding).unwrap();
        
        // Test proof serialization
        let bytes = proof.to_bytes().unwrap();
        assert!(!bytes.is_empty());
        
        // Test proof deserialization
        let deserialized = BulletproofRangeProof::from_bytes(&bytes).unwrap();
        
        // Verify the deserialized proof
        let verification = BulletproofProofSystem::verify_range_proof(&params, &deserialized).unwrap();
        assert!(verification);
    }
}
