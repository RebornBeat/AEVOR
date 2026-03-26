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
