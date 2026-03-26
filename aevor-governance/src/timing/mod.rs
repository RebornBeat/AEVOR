//! Governance timing parameters.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceTiming { pub voting_period_rounds: u64, pub execution_delay_rounds: u64, pub veto_period_rounds: u64 }
impl Default for GovernanceTiming {
    fn default() -> Self { Self { voting_period_rounds: 10_000, execution_delay_rounds: 1_000, veto_period_rounds: 500 } }
}
