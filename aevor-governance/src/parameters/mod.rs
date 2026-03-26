//! Infrastructure parameter governance.

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
