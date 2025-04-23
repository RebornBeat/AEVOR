use merlin::Transcript;
use ark_ff::{Field, PrimeField};
use ark_ec::{PairingEngine, AffineCurve, ProjectiveCurve};
use ark_groth16::{Proof as ArkProof, VerifyingKey as ArkVerifyingKey, prepare_verifying_key, prepare_inputs, verify_proof};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use serde::{Deserialize, Serialize};
use std::ops::Neg;

use crate::error::{AevorError, Result};
use super::{ProofSystem, ZkProvable, ZkVerifiable, util};

/// A Groth16 proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Groth16Proof {
    /// A proof element in G1
    pub a: Vec<u8>,
    
    /// A proof element in G2
    pub b: Vec<u8>,
    
    /// A proof element in G1
    pub c: Vec<u8>,
}

impl Groth16Proof {
    /// Creates a new Groth16 proof
    pub fn new(a: Vec<u8>, b: Vec<u8>, c: Vec<u8>) -> Self {
        Self { a, b, c }
    }
    
    /// Converts to an arkworks Proof
    pub fn to_arkworks(&self) -> Result<ArkProof<Bn254>> {
        let a: G1Affine = CanonicalDeserialize::deserialize(&mut self.a.as_slice())
            .map_err(|e| AevorError::crypto(
                "Failed to deserialize Groth16 proof A element".into(),
                e.to_string(),
                None,
            ))?;
        
        let b: G2Affine = CanonicalDeserialize::deserialize(&mut self.b.as_slice())
            .map_err(|e| AevorError::crypto(
                "Failed to deserialize Groth16 proof B element".into(),
                e.to_string(),
                None,
            ))?;
        
        let c: G1Affine = CanonicalDeserialize::deserialize(&mut self.c.as_slice())
            .map_err(|e| AevorError::crypto(
                "Failed to deserialize Groth16 proof C element".into(),
                e.to_string(),
                None,
            ))?;
        
        Ok(ArkProof { a, b, c })
    }
    
    /// Converts from an arkworks Proof
    pub fn from_arkworks(proof: &ArkProof<Bn254>) -> Result<Self> {
        let mut a_bytes = Vec::new();
        proof.a.serialize(&mut a_bytes)
            .map_err(|e| AevorError::crypto(
                "Failed to serialize Groth16 proof A element".into(),
                e.to_string(),
                None,
            ))?;
        
        let mut b_bytes = Vec::new();
        proof.b.serialize(&mut b_bytes)
            .map_err(|e| AevorError::crypto(
                "Failed to serialize Groth16 proof B element".into(),
                e.to_string(),
                None,
            ))?;
        
        let mut c_bytes = Vec::new();
        proof.c.serialize(&mut c_bytes)
            .map_err(|e| AevorError::crypto(
                "Failed to serialize Groth16 proof C element".into(),
                e.to_string(),
                None,
            ))?;
        
        Ok(Self {
            a: a_bytes,
            b: b_bytes,
            c: c_bytes,
        })
    }
    
    /// Converts from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        util::deserialize_proof(bytes)
    }
    
    /// Converts to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        util::serialize_proof(self)
    }
}

/// The verifying key for Groth16 proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyingKey {
    /// The raw verifying key data
    pub raw_data: Vec<u8>,
    
    /// The number of public inputs
    pub num_inputs: usize,
}

impl VerifyingKey {
    /// Creates a new verifying key
    pub fn new(raw_data: Vec<u8>, num_inputs: usize) -> Self {
        Self { raw_data, num_inputs }
    }
    
    /// Converts to an arkworks VerifyingKey
    pub fn to_arkworks(&self) -> Result<ArkVerifyingKey<Bn254>> {
        CanonicalDeserialize::deserialize(&mut self.raw_data.as_slice())
            .map_err(|e| AevorError::crypto(
                "Failed to deserialize Groth16 verifying key".into(),
                e.to_string(),
                None,
            ))
    }
    
    /// Converts from an arkworks VerifyingKey
    pub fn from_arkworks(vk: &ArkVerifyingKey<Bn254>) -> Result<Self> {
        let mut raw_data = Vec::new();
        vk.serialize(&mut raw_data)
            .map_err(|e| AevorError::crypto(
                "Failed to serialize Groth16 verifying key".into(),
                e.to_string(),
                None,
            ))?;
        
        Ok(Self {
            raw_data,
            num_inputs: vk.gamma_abc_g1.len() - 1,
        })
    }
    
    /// Converts from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        util::deserialize_params(bytes)
    }
    
    /// Converts to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        util::serialize_params(self)
    }
    
    /// Gets the number of public inputs
    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }
}

/// Parameters for a Groth16 proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Groth16Params {
    /// The verifying key
    pub vk: VerifyingKey,
    
    /// The public inputs
    pub public_inputs: Vec<Fr>,
}

impl Groth16Params {
    /// Creates new Groth16 parameters
    pub fn new(vk: VerifyingKey, public_inputs: Vec<Fr>) -> Self {
        Self { vk, public_inputs }
    }
    
    /// Gets the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.vk
    }
    
    /// Gets the public inputs
    pub fn public_inputs(&self) -> &[Fr] {
        &self.public_inputs
    }
    
    /// Converts from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        util::deserialize_params(bytes)
    }
    
    /// Converts to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        util::serialize_params(self)
    }
}

/// Groth16 proof system implementation
pub struct Groth16ProofSystem;

impl Groth16ProofSystem {
    /// Generate a proof using the given circuit and proving key
    pub fn generate_proof<C>(
        circuit: &C,
        proving_key: &[u8],
        transcript: &mut Transcript
    ) -> Result<Groth16Proof>
    where
        C: ConstraintSynthesizer<Fr>,
    {
        // Deserialize the proving key
        let pk = CanonicalDeserialize::deserialize(&mut proving_key.as_slice())
            .map_err(|e| AevorError::crypto(
                "Failed to deserialize Groth16 proving key".into(),
                e.to_string(),
                None,
            ))?;
        
        // Generate randomness for the proof
        let mut rng_bytes = [0u8; 32];
        transcript.challenge_bytes(b"groth16_randomness", &mut rng_bytes);
        let rng = &mut rand::rngs::StdRng::from_seed(rng_bytes);
        
        // Generate the proof
        let proof = ark_groth16::create_random_proof(circuit, &pk, rng)
            .map_err(|e| AevorError::crypto(
                "Failed to generate Groth16 proof".into(),
                e.to_string(),
                None,
            ))?;
        
        // Convert to our proof format
        Groth16Proof::from_arkworks(&proof)
    }
    
    /// Verify a Groth16 proof with public inputs
    pub fn verify(vk: &VerifyingKey, proof: &Groth16Proof) -> Result<bool> {
        // Convert to arkworks types
        let ark_vk = vk.to_arkworks()?;
        let ark_proof = proof.to_arkworks()?;
        
        // Prepare inputs for verification (empty for this example)
        // In a real implementation, you would extract public inputs from vk or elsewhere
        let public_inputs: Vec<Fr> = Vec::new();
        
        // Prepare the verifying key
        let pvk = prepare_verifying_key(&ark_vk);
        
        // Verify the proof
        Ok(verify_proof(&pvk, &ark_proof, &public_inputs).map_err(|e| {
            AevorError::crypto(
                "Failed to verify Groth16 proof".into(),
                e.to_string(),
                None,
            )
        })?)
    }
    
    /// Verify a Groth16 proof with the provided parameters
    pub fn verify_with_inputs(params: &Groth16Params, proof: &Groth16Proof) -> Result<bool> {
        // Convert to arkworks types
        let ark_vk = params.vk.to_arkworks()?;
        let ark_proof = proof.to_arkworks()?;
        let public_inputs = params.public_inputs.clone();
        
        // Prepare the verifying key
        let pvk = prepare_verifying_key(&ark_vk);
        
        // Verify the proof
        Ok(verify_proof(&pvk, &ark_proof, &public_inputs).map_err(|e| {
            AevorError::crypto(
                "Failed to verify Groth16 proof".into(),
                e.to_string(),
                None,
            )
        })?)
    }
}

impl ProofSystem<VerifyingKey, Groth16Proof> for Groth16ProofSystem {
    fn verify(vk: &VerifyingKey, proof: &Groth16Proof) -> Result<bool> {
        Self::verify(vk, proof)
    }
}

/// A simple example circuit implementation for testing
#[cfg(test)]
pub struct TestCircuit {
    /// The secret input
    pub a: Fr,
    /// The secret input
    pub b: Fr,
    /// The public input/output
    pub c: Fr,
}

#[cfg(test)]
impl ConstraintSynthesizer<Fr> for TestCircuit {
    fn generate_constraints(self, cs: &mut ConstraintSystem<Fr>) -> ark_relations::r1cs::Result<()> {
        // Allocate the private inputs
        let a = cs.new_witness_variable(|| Ok(self.a))?;
        let b = cs.new_witness_variable(|| Ok(self.b))?;
        
        // Allocate the public input/output
        let c = cs.new_input_variable(|| Ok(self.c))?;
        
        // Enforce that a * b = c
        cs.enforce(
            || "a * b = c",
            |lc| lc + a,
            |lc| lc + b,
            |lc| lc + c,
        );
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;
    use ark_std::UniformRand;
    use ark_groth16::{generate_random_parameters, ProvingKey};
    
    // Helper function to generate test parameters
    fn generate_test_parameters() -> (Groth16Proof, Groth16Params) {
        // Create a test circuit
        let a = Fr::from(2u32);
        let b = Fr::from(3u32);
        let c = Fr::from(6u32); // a * b = c
        
        let circuit = TestCircuit { a, b, c };
        
        // Generate proving and verifying keys
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let params = generate_random_parameters::<Bn254, _, _>(circuit.clone(), &mut rng).unwrap();
        
        // Generate a proof
        let proof = ark_groth16::create_random_proof(circuit, &params, &mut rng).unwrap();
        
        // Prepare parameters for verification
        let vk = VerifyingKey::from_arkworks(&params.vk).unwrap();
        let public_inputs = vec![c];
        let params = Groth16Params::new(vk, public_inputs);
        
        // Convert to our proof format
        let proof = Groth16Proof::from_arkworks(&proof).unwrap();
        
        (proof, params)
    }
    
    #[test]
    fn test_groth16_proof_serialization() {
        let (proof, _) = generate_test_parameters();
        
        // Test serialization and deserialization
        let serialized = proof.to_bytes().unwrap();
        let deserialized = Groth16Proof::from_bytes(&serialized).unwrap();
        
        // Convert both to arkworks for comparison
        let ark_original = proof.to_arkworks().unwrap();
        let ark_deserialized = deserialized.to_arkworks().unwrap();
        
        // The points should be equal
        assert_eq!(ark_original.a, ark_deserialized.a);
        assert_eq!(ark_original.b, ark_deserialized.b);
        assert_eq!(ark_original.c, ark_deserialized.c);
    }
    
    #[test]
    fn test_verifying_key_serialization() {
        let (_, params) = generate_test_parameters();
        let vk = params.verifying_key();
        
        // Test serialization and deserialization
        let serialized = vk.to_bytes().unwrap();
        let deserialized = VerifyingKey::from_bytes(&serialized).unwrap();
        
        // Convert both to arkworks for comparison
        let ark_original = vk.to_arkworks().unwrap();
        let ark_deserialized = deserialized.to_arkworks().unwrap();
        
        // The keys should be equal (checking a few fields)
        assert_eq!(ark_original.alpha_g1, ark_deserialized.alpha_g1);
        assert_eq!(ark_original.beta_g2, ark_deserialized.beta_g2);
        assert_eq!(ark_original.gamma_g2, ark_deserialized.gamma_g2);
        assert_eq!(ark_original.delta_g2, ark_deserialized.delta_g2);
        assert_eq!(ark_original.gamma_abc_g1.len(), ark_deserialized.gamma_abc_g1.len());
    }
    
    #[test]
    fn test_groth16_proof_verification() {
        let (proof, params) = generate_test_parameters();
        
        // Verify the proof
        let result = Groth16ProofSystem::verify_with_inputs(&params, &proof).unwrap();
        assert!(result, "Proof verification should succeed");
        
        // Test with invalid public input
        let invalid_c = Fr::from(7u32); // Not equal to a * b
        let invalid_params = Groth16Params::new(params.vk.clone(), vec![invalid_c]);
        
        let result = Groth16ProofSystem::verify_with_inputs(&invalid_params, &proof).unwrap();
        assert!(!result, "Proof verification should fail with invalid input");
    }
    
    #[test]
    fn test_groth16_proof_system_trait() {
        let (proof, params) = generate_test_parameters();
        
        // Test the ProofSystem trait implementation
        let result = Groth16ProofSystem::verify(&params.vk, &proof).unwrap();
        assert!(result, "Proof verification through trait should succeed");
    }
    
    #[test]
    fn test_groth16_params_serialization() {
        let (_, params) = generate_test_parameters();
        
        // Test serialization and deserialization
        let serialized = params.to_bytes().unwrap();
        let deserialized = Groth16Params::from_bytes(&serialized).unwrap();
        
        // Check that the number of inputs is preserved
        assert_eq!(params.vk.num_inputs(), deserialized.vk.num_inputs());
        
        // Check that the public inputs are preserved
        assert_eq!(params.public_inputs.len(), deserialized.public_inputs.len());
        for (a, b) in params.public_inputs.iter().zip(deserialized.public_inputs.iter()) {
            assert_eq!(a.into_repr(), b.into_repr());
        }
    }
}
