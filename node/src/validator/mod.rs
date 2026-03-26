//! Validator node orchestration.
use serde::{Deserialize, Serialize};
use aevor_core::tee::TeePlatform;
use crate::NodeResult;

pub struct ConsensusHandle { pub active: bool }
pub struct ValidatorTeeHandle { pub platform: TeePlatform }

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub enum ValidatorState { #[default] Initializing, Active, Paused, Stopping }

pub struct ValidatorOrchestrator { consensus: Option<ConsensusHandle> }
impl ValidatorOrchestrator {
    pub fn new() -> Self { Self { consensus: None } }
    pub fn is_active(&self) -> bool { self.consensus.as_ref().map(|c| c.active).unwrap_or(false) }
}
impl Default for ValidatorOrchestrator { fn default() -> Self { Self::new() } }

pub struct ValidatorNode { state: ValidatorState }
impl ValidatorNode {
    pub fn new() -> Self { Self { state: ValidatorState::Initializing } }
    pub fn state(&self) -> ValidatorState { self.state }
}
impl Default for ValidatorNode { fn default() -> Self { Self::new() } }
