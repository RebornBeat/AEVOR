//! Move cross-chain interoperability extensions.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossChainModule { pub name: String, pub target_chain: String }
