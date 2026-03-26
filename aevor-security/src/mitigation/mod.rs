//! Automatic threat mitigation actions.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MitigationResult { pub action_taken: String, pub success: bool }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsolationAction { pub target: Hash256, pub duration_epochs: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThrottleAction { pub target: Hash256, pub rate_limit_pct: u8 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BanAction { pub target: Hash256, pub permanent: bool }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MitigationStrategy {
    Isolate(IsolationAction),
    Throttle(ThrottleAction),
    Ban(BanAction),
    Alert(String),
    NoAction,
}

pub struct AutomaticMitigation { strategies: Vec<MitigationStrategy> }
impl AutomaticMitigation {
    pub fn new() -> Self { Self { strategies: Vec::new() } }
    pub fn add(&mut self, s: MitigationStrategy) { self.strategies.push(s); }
    pub fn strategy_count(&self) -> usize { self.strategies.len() }
}
impl Default for AutomaticMitigation { fn default() -> Self { Self::new() } }
