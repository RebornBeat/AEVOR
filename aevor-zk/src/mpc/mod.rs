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
