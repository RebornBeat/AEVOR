//! Cross-contract execution coordination in the pipeline.
use serde::{Deserialize, Serialize};
use aevor_core::primitives::Address;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossContractExecution { pub caller: Address, pub callee: Address }
