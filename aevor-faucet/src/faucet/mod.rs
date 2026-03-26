//! Faucet core: request processing and distribution.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Amount};
use crate::{FaucetError, FaucetResult};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaucetConfig {
    pub network: String,
    pub node_endpoint: String,
    pub distribution_amount: u64,
    pub cooldown_seconds: u64,
    pub pow_difficulty: u32,
    pub key_file: Option<std::path::PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistributionRequest {
    pub recipient: Address,
    pub pow_solution: crate::pow::PowSolution,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistributionResult {
    pub tx_hash: aevor_core::primitives::Hash256,
    pub amount: Amount,
    pub recipient: Address,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaucetBalance { pub available: Amount }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaucetStatus {
    pub network: String,
    pub balance: FaucetBalance,
    pub requests_served: u64,
    pub cooldown_seconds: u64,
}

pub struct Faucet { config: FaucetConfig }
impl Faucet {
    pub async fn new(config: FaucetConfig) -> FaucetResult<Self> {
        if config.network == "mainnet" {
            return Err(FaucetError::NetworkNotSupported { network: config.network.clone() });
        }
        Ok(Self { config })
    }
    pub fn config(&self) -> &FaucetConfig { &self.config }
}
