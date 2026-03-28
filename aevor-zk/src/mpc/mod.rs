//! Multi-party computation coordination.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcParty { pub id: Hash256, pub public_share: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcInput { pub party: Hash256, pub encrypted: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcOutput { pub result: Vec<u8>, pub proof: Vec<u8> }

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum MpcProtocol { Shamir, BeaverTriple, Gmw }

pub struct SecureAggregation;
pub struct PrivacyPreservingMpc;
pub struct TeeEnhancedMpc;

pub struct MpcCoordinator { parties: Vec<MpcParty> }
impl MpcCoordinator {
    pub fn new() -> Self { Self { parties: Vec::new() } }
    pub fn add_party(&mut self, p: MpcParty) { self.parties.push(p); }
    pub fn party_count(&self) -> usize { self.parties.len() }
}
impl Default for MpcCoordinator { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn party(n: u8) -> MpcParty { MpcParty { id: Hash256([n; 32]), public_share: vec![n; 32] } }

    #[test]
    fn mpc_coordinator_add_parties() {
        let mut coord = MpcCoordinator::new();
        coord.add_party(party(1));
        coord.add_party(party(2));
        assert_eq!(coord.party_count(), 2);
    }

    #[test]
    fn mpc_protocols_distinct() {
        assert!(!matches!(MpcProtocol::Shamir, MpcProtocol::BeaverTriple));
        assert!(!matches!(MpcProtocol::Gmw, MpcProtocol::Shamir));
    }

    #[test]
    fn mpc_output_stores_result_and_proof() {
        let out = MpcOutput { result: vec![1,2,3], proof: vec![0xAB; 32] };
        assert_eq!(out.result, vec![1,2,3]);
        assert_eq!(out.proof.len(), 32);
    }
}
