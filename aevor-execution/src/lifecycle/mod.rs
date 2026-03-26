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
