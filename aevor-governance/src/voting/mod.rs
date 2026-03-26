//! Privacy-preserving voting.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Hash256, ValidatorId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice { Yes, No, Abstain, Veto }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub proposal_id: Hash256, pub voter: Address, pub choice: VoteChoice,
    pub weight: aevor_core::primitives::ValidatorWeight,
}

pub type VoteWeight = aevor_core::primitives::ValidatorWeight;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteTally {
    pub yes_weight: u64, pub no_weight: u64, pub abstain_weight: u64, pub veto_weight: u64,
    pub total_weight: u64,
}
impl VoteTally {
    pub fn yes_fraction(&self) -> f64 {
        if self.total_weight == 0 { 0.0 } else { self.yes_weight as f64 / self.total_weight as f64 }
    }
    pub fn passed(&self, threshold_pct: u8) -> bool {
        self.yes_fraction() * 100.0 >= threshold_pct as f64
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateVote { pub commitment: Hash256, pub proof: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteEncryption { pub encrypted_choice: Vec<u8>, pub nonce: [u8; 32] }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteDecryption { pub choice: VoteChoice, pub proof: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TallyProof { pub tally: VoteTally, pub proof: Vec<u8> }
