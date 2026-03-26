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
            .take((challenge.difficulty.0 as usize + 7) / 8)
            .map(|b| b.leading_zeros())
            .sum::<u32>();
        leading_zeros >= challenge.difficulty.0
    }
}

pub struct ChallengeGenerator { difficulty: u32 }
impl ChallengeGenerator {
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
}
