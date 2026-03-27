//! Proof-of-work challenge for bot resistance.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;
use crate::{FaucetError, FaucetResult, DEFAULT_POW_DIFFICULTY};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowDifficulty(pub u32);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowChallenge {
    pub challenge_hash: Hash256,
    pub difficulty: PowDifficulty,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowSolution {
    pub challenge_hash: Hash256,
    pub nonce: u64,
    pub solution_hash: Hash256,
}

pub struct PowVerifier;
impl PowVerifier {
    pub fn verify(challenge: &PowChallenge, solution: &PowSolution) -> bool {
        if solution.challenge_hash != challenge.challenge_hash { return false; }
        let leading_zeros = solution.solution_hash.0.iter()
            .take((challenge.difficulty.0 as usize).div_ceil(8))
            .map(|b| b.leading_zeros())
            .sum::<u32>();
        leading_zeros >= challenge.difficulty.0
    }
}

pub struct ChallengeGenerator { difficulty: u32 }
impl ChallengeGenerator {
    /// Create a generator using the library's default difficulty.
    pub fn default_difficulty() -> Self { Self { difficulty: DEFAULT_POW_DIFFICULTY } }
    pub fn new(difficulty: u32) -> Self { Self { difficulty } }
    pub fn generate(&self) -> PowChallenge {
        let mut challenge_bytes = [0u8; 32];
        getrandom::getrandom(&mut challenge_bytes).ok();
        PowChallenge {
            challenge_hash: Hash256(challenge_bytes),
            difficulty: PowDifficulty(self.difficulty),
            expires_at_unix: 0,
        }
    }
    /// Verify a solution, returning a `FaucetResult`.
    ///
    /// # Errors
    /// Returns `FaucetError::InvalidProofOfWork` if the solution hash does not
    /// meet the required difficulty (insufficient leading zero bits).
    pub fn verify_solution(&self, challenge: &PowChallenge, solution: &PowSolution) -> FaucetResult<()> {
        if !PowVerifier::verify(challenge, solution) {
            return Err(FaucetError::InvalidProofOfWork {
                reason: "solution does not meet difficulty requirement".into(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn make_challenge(difficulty: u32) -> PowChallenge {
        PowChallenge {
            challenge_hash: Hash256([0xAB; 32]),
            difficulty: PowDifficulty(difficulty),
            expires_at_unix: 9_999_999,
        }
    }

    #[test]
    fn verifier_rejects_wrong_challenge_hash() {
        let challenge = make_challenge(8);
        let solution = PowSolution {
            challenge_hash: Hash256([0xFF; 32]), // wrong
            nonce: 0,
            solution_hash: Hash256([0u8; 32]),
        };
        assert!(!PowVerifier::verify(&challenge, &solution));
    }

    #[test]
    fn verifier_accepts_solution_with_enough_leading_zeros() {
        // difficulty=8: solution hash must have at least 8 leading zero bits
        // [0x00, ...] has 8 leading zero bits in the first byte
        let challenge = make_challenge(8);
        let solution = PowSolution {
            challenge_hash: challenge.challenge_hash,
            nonce: 42,
            solution_hash: Hash256([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        };
        assert!(PowVerifier::verify(&challenge, &solution));
    }

    #[test]
    fn verifier_rejects_insufficient_leading_zeros() {
        let challenge = make_challenge(16); // need 16 leading zero bits
        let solution = PowSolution {
            challenge_hash: challenge.challenge_hash,
            nonce: 0,
            // Only 8 leading zero bits (first byte 0x00, second 0xFF)
            solution_hash: Hash256([0x00, 0xFF, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0]),
        };
        assert!(!PowVerifier::verify(&challenge, &solution));
    }

    #[test]
    fn generator_produces_challenge_with_configured_difficulty() {
        let gen = ChallengeGenerator::new(12);
        let challenge = gen.generate();
        assert_eq!(challenge.difficulty.0, 12);
    }

    #[test]
    fn verify_solution_returns_error_for_bad_solution() {
        let gen = ChallengeGenerator::new(8);
        let challenge = make_challenge(8);
        let bad_solution = PowSolution {
            challenge_hash: Hash256([0xAB; 32]),
            nonce: 0,
            solution_hash: Hash256([0xFF; 32]), // no leading zeros
        };
        assert!(gen.verify_solution(&challenge, &bad_solution).is_err());
    }
}
