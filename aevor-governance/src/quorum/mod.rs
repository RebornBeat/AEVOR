//! Quorum calculation for governance votes.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::ValidatorWeight;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumRequirement { pub min_participation_pct: u8, pub approval_threshold_pct: u8 }
impl Default for QuorumRequirement {
    fn default() -> Self { Self { min_participation_pct: 33, approval_threshold_pct: 67 } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumCheck { pub participated_weight: ValidatorWeight, pub total_weight: ValidatorWeight }
impl QuorumCheck {
    #[allow(clippy::cast_possible_truncation)] // result is always 0–100 so truncation to u8 is safe
    pub fn participation_pct(&self) -> u8 {
        if self.total_weight.as_u64() == 0 { 0 }
        else { (self.participated_weight.as_u64() * 100 / self.total_weight.as_u64()) as u8 }
    }
    pub fn meets_quorum(&self, req: &QuorumRequirement) -> bool {
        self.participation_pct() >= req.min_participation_pct
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumProof { pub check: QuorumCheck, pub proof: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipationRate { pub rate_pct: u8 }
pub struct StakeWeightedQuorum;

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::ValidatorWeight;

    fn check(participated: u64, total: u64) -> QuorumCheck {
        QuorumCheck { participated_weight: ValidatorWeight::from_u64(participated), total_weight: ValidatorWeight::from_u64(total) }
    }

    #[test]
    fn quorum_requirement_default_sensible() {
        let q = QuorumRequirement::default();
        assert_eq!(q.min_participation_pct, 33);
        assert_eq!(q.approval_threshold_pct, 67);
    }

    #[test]
    fn quorum_check_participation_pct() {
        assert_eq!(check(33, 100).participation_pct(), 33);
        assert_eq!(check(50, 100).participation_pct(), 50);
        assert_eq!(check(0, 100).participation_pct(), 0);
    }

    #[test]
    fn quorum_check_zero_total_returns_zero() {
        assert_eq!(check(0, 0).participation_pct(), 0);
    }

    #[test]
    fn quorum_check_meets_quorum_at_threshold() {
        let req = QuorumRequirement { min_participation_pct: 33, approval_threshold_pct: 67 };
        assert!(check(33, 100).meets_quorum(&req));
        assert!(!check(32, 100).meets_quorum(&req));
    }
}
