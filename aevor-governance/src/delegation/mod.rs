//! Vote delegation.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Hash256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationRecord { pub delegator: Address, pub delegate: Address, pub active: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationChain { pub chain: Vec<Address> }
impl DelegationChain {
    pub fn depth(&self) -> usize { self.chain.len() }
    pub fn final_delegate(&self) -> Option<&Address> { self.chain.last() }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeDelegation { pub delegator: Address, pub effective_round: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateDelegation { pub commitment: Hash256 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationProof { pub proof: Vec<u8> }

pub struct Delegation { records: Vec<DelegationRecord> }
impl Delegation {
    pub fn new() -> Self { Self { records: Vec::new() } }
    pub fn delegate(&mut self, delegator: Address, delegate: Address) {
        self.records.push(DelegationRecord { delegator, delegate, active: true });
    }
    pub fn active_delegate(&self, delegator: &Address) -> Option<&Address> {
        self.records.iter().find(|r| &r.delegator == delegator && r.active).map(|r| &r.delegate)
    }
}
impl Default for Delegation { fn default() -> Self { Self::new() } }
