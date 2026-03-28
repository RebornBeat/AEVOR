//! Privacy-preserving voting.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Hash256, ValidatorId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice { Yes, No, Abstain, Veto }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub proposal_id: Hash256, pub voter: Address, pub choice: VoteChoice,
    pub weight: aevor_core::primitives::ValidatorWeight,
    /// The validator identity associated with this vote (for validator-set governance).
    pub validator_id: Option<ValidatorId>,
}

pub type VoteWeight = aevor_core::primitives::ValidatorWeight;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteTally {
    pub yes_weight: u64, pub no_weight: u64, pub abstain_weight: u64, pub veto_weight: u64,
    pub total_weight: u64,
}
impl VoteTally {
    #[allow(clippy::cast_precision_loss)] // vote weights: u64→f64 precision loss acceptable for ratios
    pub fn yes_fraction(&self) -> f64 {
        if self.total_weight == 0 { 0.0 } else { self.yes_weight as f64 / self.total_weight as f64 }
    }
    pub fn passed(&self, threshold_pct: u8) -> bool {
        self.yes_fraction() * 100.0 >= f64::from(threshold_pct)
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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, Hash256, ValidatorWeight};

    fn addr(n: u8) -> Address { Address([n; 32]) }

    fn vote(choice: VoteChoice, weight: u64) -> Vote {
        Vote {
            proposal_id: Hash256::ZERO,
            voter: addr(1),
            choice,
            weight: ValidatorWeight::from_u64(weight),
            validator_id: None,
        }
    }

    #[test]
    fn vote_choice_variants_distinct() {
        assert_ne!(VoteChoice::Yes, VoteChoice::No);
        assert_ne!(VoteChoice::Abstain, VoteChoice::Veto);
    }

    #[test]
    fn vote_tally_yes_fraction_all_yes() {
        let t = VoteTally { yes_weight: 100, no_weight: 0, abstain_weight: 0, veto_weight: 0, total_weight: 100 };
        assert!((t.yes_fraction() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn vote_tally_yes_fraction_majority() {
        let t = VoteTally { yes_weight: 60, no_weight: 40, abstain_weight: 0, veto_weight: 0, total_weight: 100 };
        assert!((t.yes_fraction() - 0.6).abs() < 1e-9);
    }

    #[test]
    fn vote_tally_passes_above_threshold() {
        let t = VoteTally { yes_weight: 70, no_weight: 30, abstain_weight: 0, veto_weight: 0, total_weight: 100 };
        assert!(t.passed(67)); // 70% > 67%
        assert!(!t.passed(71)); // 70% < 71%
    }

    #[test]
    fn vote_tally_zero_total_does_not_pass() {
        let t = VoteTally { yes_weight: 0, no_weight: 0, abstain_weight: 0, veto_weight: 0, total_weight: 0 };
        assert!(!t.passed(50));
    }

    #[test]
    fn vote_stores_weight_and_choice() {
        let v = vote(VoteChoice::Yes, 100);
        assert_eq!(v.choice, VoteChoice::Yes);
        assert_eq!(v.weight.as_u64(), 100);
    }

    #[test]
    fn private_vote_stores_commitment_and_proof() {
        let pv = PrivateVote { commitment: Hash256([0xAB; 32]), proof: vec![1,2,3] };
        assert_eq!(pv.commitment, Hash256([0xAB; 32]));
        assert!(!pv.proof.is_empty());
    }

    #[test]
    fn tally_proof_includes_zk_proof() {
        let t = VoteTally { yes_weight: 100, no_weight: 0, abstain_weight: 0, veto_weight: 0, total_weight: 100 };
        let tp = TallyProof { tally: t, proof: vec![0xBE; 64] };
        assert!(!tp.proof.is_empty());
        assert!(tp.tally.passed(50));
    }
}
