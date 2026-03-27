//! Validator node orchestration.
use serde::{Deserialize, Serialize};
use aevor_core::tee::TeePlatform;
use crate::NodeResult;

#[derive(Debug)]
pub struct ConsensusHandle { pub active: bool }
#[derive(Debug)]
pub struct ValidatorTeeHandle { pub platform: TeePlatform }

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub enum ValidatorState { #[default] Initializing, Active, Paused, Stopping }

#[derive(Debug)]
pub struct ValidatorOrchestrator { consensus: Option<ConsensusHandle> }
impl ValidatorOrchestrator {
    pub fn new() -> Self { Self { consensus: None } }
    pub fn is_active(&self) -> bool { self.consensus.as_ref().is_some_and(|c| c.active) }
}
impl Default for ValidatorOrchestrator { fn default() -> Self { Self::new() } }

#[derive(Debug)]
pub struct ValidatorNode { state: ValidatorState }
impl ValidatorNode {
    pub fn new() -> Self { Self { state: ValidatorState::Initializing } }
    pub fn state(&self) -> ValidatorState { self.state }
    /// Transition from Initializing to Active, returning an error if the state is wrong.
    ///
    /// # Errors
    /// Returns `NodeError::InitializationFailed` if the validator is not in
    /// `Initializing` or `Paused` state.
    pub fn activate(&mut self) -> NodeResult<()> {
        if !matches!(self.state, ValidatorState::Initializing | ValidatorState::Paused) {
            return Err(crate::NodeError::InitializationFailed {
                subsystem: "validator-node".into(),
                reason: format!("cannot activate from state {state:?}", state = self.state),
            });
        }
        self.state = ValidatorState::Active;
        Ok(())
    }
}
impl Default for ValidatorNode { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_starts_in_initializing_state() {
        let v = ValidatorNode::new();
        assert!(matches!(v.state(), ValidatorState::Initializing));
    }

    #[test]
    fn activate_from_initializing_succeeds() {
        let mut v = ValidatorNode::new();
        assert!(v.activate().is_ok());
        assert!(matches!(v.state(), ValidatorState::Active));
    }

    #[test]
    fn activate_from_active_fails() {
        let mut v = ValidatorNode::new();
        v.activate().unwrap();
        assert!(v.activate().is_err());
    }

    #[test]
    fn orchestrator_without_consensus_is_inactive() {
        let o = ValidatorOrchestrator::new();
        assert!(!o.is_active());
    }

    #[test]
    fn orchestrator_with_active_consensus_is_active() {
        let o = ValidatorOrchestrator { consensus: Some(ConsensusHandle { active: true }) };
        assert!(o.is_active());
    }

    #[test]
    fn orchestrator_with_inactive_consensus_is_not_active() {
        let o = ValidatorOrchestrator { consensus: Some(ConsensusHandle { active: false }) };
        assert!(!o.is_active());
    }
}
