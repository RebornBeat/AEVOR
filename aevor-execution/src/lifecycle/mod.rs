//! Smart contract lifecycle management.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, BlockHeight, Hash256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeploymentRecord { pub address: Address, pub bytecode_hash: Hash256, pub height: BlockHeight }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpgradeRecord { pub address: Address, pub old_hash: Hash256, pub new_hash: Hash256, pub height: BlockHeight }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DestroyRecord { pub address: Address, pub height: BlockHeight }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LifecycleEvent { Deployed(DeploymentRecord), Upgraded(UpgradeRecord), Destroyed(DestroyRecord) }

pub struct LifecycleValidator;
impl LifecycleValidator {
    pub fn validate_deploy(record: &DeploymentRecord) -> bool { !record.bytecode_hash.is_zero() }
}

pub struct ContractLifecycle { events: Vec<LifecycleEvent> }
impl ContractLifecycle {
    pub fn new() -> Self { Self { events: Vec::new() } }
    pub fn add_event(&mut self, e: LifecycleEvent) { self.events.push(e); }
    pub fn event_count(&self) -> usize { self.events.len() }
}
impl Default for ContractLifecycle { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, BlockHeight, Hash256};

    fn addr(n: u8) -> Address { Address([n; 32]) }
    fn bh(n: u64) -> BlockHeight { BlockHeight(n) }

    #[test]
    fn lifecycle_validator_accepts_nonempty_hash() {
        let r = DeploymentRecord { address: addr(1), bytecode_hash: Hash256([1u8; 32]), height: bh(100) };
        assert!(LifecycleValidator::validate_deploy(&r));
    }

    #[test]
    fn lifecycle_validator_rejects_zero_hash() {
        let r = DeploymentRecord { address: addr(1), bytecode_hash: Hash256::ZERO, height: bh(100) };
        assert!(!LifecycleValidator::validate_deploy(&r));
    }

    #[test]
    fn contract_lifecycle_add_events() {
        let mut lc = ContractLifecycle::new();
        lc.add_event(LifecycleEvent::Deployed(DeploymentRecord { address: addr(1), bytecode_hash: Hash256([1u8;32]), height: bh(50) }));
        lc.add_event(LifecycleEvent::Destroyed(DestroyRecord { address: addr(1), height: bh(200) }));
        assert_eq!(lc.event_count(), 2);
    }

    #[test]
    fn upgrade_record_stores_old_and_new_hash() {
        let r = UpgradeRecord { address: addr(1), old_hash: Hash256([1u8;32]), new_hash: Hash256([2u8;32]), height: bh(150) };
        assert_ne!(r.old_hash, r.new_hash);
    }
}
