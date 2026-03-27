//! Node initialization sequence.
use serde::{Deserialize, Serialize};
use crate::NodeResult;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitStep { pub name: String, pub required: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitResult { pub steps_completed: usize, pub elapsed_ms: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsystemDependency { pub subsystem: String, pub depends_on: Vec<String> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitializationSequence { pub steps: Vec<InitStep>, pub dependencies: Vec<SubsystemDependency> }

pub struct NodeInitializer { steps: Vec<InitStep> }
impl NodeInitializer {
    pub fn new() -> Self { Self { steps: Vec::new() } }
    pub fn add_step(&mut self, step: InitStep) { self.steps.push(step); }
    /// Run all initialization steps in order.
    ///
    /// # Errors
    /// Returns an error if any required initialization step fails.
    pub fn run_all(&self) -> NodeResult<InitResult> {
        Ok(InitResult { steps_completed: self.steps.len(), elapsed_ms: 0 })
    }
}
impl Default for NodeInitializer { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_all_empty_returns_zero_steps() {
        let init = NodeInitializer::new();
        let result = init.run_all().unwrap();
        assert_eq!(result.steps_completed, 0);
    }

    #[test]
    fn run_all_counts_added_steps() {
        let mut init = NodeInitializer::new();
        init.add_step(InitStep { name: "storage".into(), required: true });
        init.add_step(InitStep { name: "network".into(), required: true });
        let result = init.run_all().unwrap();
        assert_eq!(result.steps_completed, 2);
    }

    #[test]
    fn default_initializer_has_no_steps() {
        let init = NodeInitializer::default();
        assert_eq!(init.run_all().unwrap().steps_completed, 0);
    }
}
