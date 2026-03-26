//! Move-chain (Aptos/Sui) bridge.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveChainConfig { pub chain_id: String, pub rpc_url: String }
pub struct MoveChainBridge { config: MoveChainConfig }
impl MoveChainBridge { pub fn new(c: MoveChainConfig) -> Self { Self { config: c } } }
