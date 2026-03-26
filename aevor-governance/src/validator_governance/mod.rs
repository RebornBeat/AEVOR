//! Validator set governance.
use serde::{Deserialize, Serialize};
use aevor_core::primitives::ValidatorId;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorAdmission { pub validator: ValidatorId, pub approved: bool }
