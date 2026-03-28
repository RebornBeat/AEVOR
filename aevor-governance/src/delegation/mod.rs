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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Address;

    fn addr(n: u8) -> Address { Address([n; 32]) }

    #[test]
    fn delegation_stores_and_retrieves() {
        let mut d = Delegation::new();
        d.delegate(addr(1), addr(2));
        assert_eq!(d.active_delegate(&addr(1)), Some(&addr(2)));
    }

    #[test]
    fn delegation_no_record_returns_none() {
        let d = Delegation::default();
        assert!(d.active_delegate(&addr(99)).is_none());
    }

    #[test]
    fn delegation_chain_depth_and_final_delegate() {
        let chain = DelegationChain { chain: vec![addr(1), addr(2), addr(3)] };
        assert_eq!(chain.depth(), 3);
        assert_eq!(chain.final_delegate(), Some(&addr(3)));
    }

    #[test]
    fn delegation_chain_empty_final_delegate_is_none() {
        let chain = DelegationChain { chain: vec![] };
        assert!(chain.final_delegate().is_none());
    }

    #[test]
    fn revoke_delegation_stores_fields() {
        let r = RevokeDelegation { delegator: addr(1), effective_round: 100 };
        assert_eq!(r.effective_round, 100);
    }

    #[test]
    fn private_delegation_commitment() {
        use aevor_core::primitives::Hash256;
        let pd = PrivateDelegation { commitment: Hash256([0xAB; 32]) };
        assert_eq!(pd.commitment, Hash256([0xAB; 32]));
    }
}
