//! Graceful shutdown sequence.
use serde::{Deserialize, Serialize};
use crate::NodeResult;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ShutdownReason { Signal, Error, Planned }
impl std::fmt::Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Signal => write!(f, "signal"), Self::Error => write!(f, "error"), Self::Planned => write!(f, "planned") }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShutdownTimeout { pub subsystem: String, pub timeout_ms: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatePreservation { pub state_saved: bool, pub checkpoint_created: bool }

pub struct ShutdownSequence { subsystems: Vec<String> }
impl ShutdownSequence {
    pub fn new(subsystems: Vec<String>) -> Self { Self { subsystems } }
    pub async fn execute(&self) -> NodeResult<StatePreservation> {
        Ok(StatePreservation { state_saved: true, checkpoint_created: true })
    }
}

pub struct GracefulShutdown;
impl GracefulShutdown {
    pub async fn shutdown(reason: ShutdownReason) -> NodeResult<()> { Ok(()) }
}
