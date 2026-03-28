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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn target(n: u8) -> Hash256 { Hash256([n; 32]) }

    #[test]
    fn automatic_mitigation_add_and_count() {
        let mut am = AutomaticMitigation::new();
        am.add(MitigationStrategy::Isolate(IsolationAction { target: target(1), duration_epochs: 10 }));
        am.add(MitigationStrategy::Alert("high anomaly score".into()));
        assert_eq!(am.strategy_count(), 2);
    }

    #[test]
    fn mitigation_strategy_ban_permanent() {
        let ban = MitigationStrategy::Ban(BanAction { target: target(5), permanent: true });
        assert!(matches!(ban, MitigationStrategy::Ban(a) if a.permanent));
    }

    #[test]
    fn mitigation_strategy_throttle_rate() {
        let t = ThrottleAction { target: target(2), rate_limit_pct: 10 };
        assert_eq!(t.rate_limit_pct, 10);
    }

    #[test]
    fn mitigation_result_success_and_failure() {
        let ok = MitigationResult { action_taken: "isolated validator".into(), success: true };
        assert!(ok.success);
        let fail = MitigationResult { action_taken: "throttle".into(), success: false };
        assert!(!fail.success);
    }

    #[test]
    fn no_action_strategy() {
        let s = MitigationStrategy::NoAction;
        assert!(matches!(s, MitigationStrategy::NoAction));
    }
}
