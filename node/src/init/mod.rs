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
    pub async fn run_all(&self) -> NodeResult<InitResult> {
        Ok(InitResult { steps_completed: self.steps.len(), elapsed_ms: 0 })
    }
}
impl Default for NodeInitializer { fn default() -> Self { Self::new() } }
