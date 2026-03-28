//! Infrastructure parameter governance.
//!
//! All infrastructure parameters are governance-adjustable through proposals —
//! there are no hardcoded values here. This embodies the whitepaper principle:
//! "economic capabilities provide primitives that enable applications to
//! implement any economic model."

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InfrastructureParameter { pub key: String, pub value: Vec<u8>, pub description: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParameterRange { pub key: String, pub min: Vec<u8>, pub max: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParameterChange { pub parameter: InfrastructureParameter, pub new_value: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParameterSimulation { pub change: ParameterChange, pub projected_impact: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParameterChangeProposal { pub changes: Vec<ParameterChange>, pub rationale: String }

#[cfg(test)]
mod tests {
    use super::*;

    fn param(key: &str, value: &[u8]) -> InfrastructureParameter {
        InfrastructureParameter {
            key: key.into(),
            value: value.to_vec(),
            description: format!("parameter {key}"),
        }
    }

    // ── InfrastructureParameter ───────────────────────────────────────────
    // Whitepaper: governance provides "parameter change proposals and execution"

    #[test]
    fn parameter_stores_key_value_description() {
        let p = param("min_gas_price", &100u64.to_le_bytes());
        assert_eq!(p.key, "min_gas_price");
        assert_eq!(p.value, 100u64.to_le_bytes().to_vec());
    }

    #[test]
    fn parameter_range_defines_governance_bounds() {
        let range = ParameterRange {
            key: "block_gas_limit".into(),
            min: 1_000_000u64.to_le_bytes().to_vec(),
            max: u64::MAX.to_le_bytes().to_vec(), // no artificial ceiling
        };
        assert_eq!(range.key, "block_gas_limit");
        assert!(range.max > range.min);
    }

    #[test]
    fn parameter_change_proposal_bundles_multiple_changes() {
        let proposal = ParameterChangeProposal {
            changes: vec![
                ParameterChange {
                    parameter: param("base_fee_nano", &500u64.to_le_bytes()),
                    new_value: 1_000u64.to_le_bytes().to_vec(),
                },
                ParameterChange {
                    parameter: param("min_gas_price_nano", &50u64.to_le_bytes()),
                    new_value: 100u64.to_le_bytes().to_vec(),
                },
            ],
            rationale: "Adjust fee parameters to reflect network conditions".into(),
        };
        assert_eq!(proposal.changes.len(), 2);
        assert!(!proposal.rationale.is_empty());
    }

    #[test]
    fn parameter_simulation_records_projected_impact() {
        let sim = ParameterSimulation {
            change: ParameterChange {
                parameter: param("annual_inflation_bps", &500u32.to_le_bytes()),
                new_value: 300u32.to_le_bytes().to_vec(),
            },
            projected_impact: "Reduce inflation from 5% to 3%; validator rewards decrease ~2%".into(),
        };
        assert!(!sim.projected_impact.is_empty());
        assert_eq!(sim.change.parameter.key, "annual_inflation_bps");
    }
}
