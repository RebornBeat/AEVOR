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
    pub fn new(config: FaucetConfig) -> FaucetResult<Self> {
        if config.network == "mainnet" {
            return Err(FaucetError::NetworkNotSupported { network: config.network.clone() });
        }
        Ok(Self { config })
    }
    pub fn config(&self) -> &FaucetConfig { &self.config }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Amount;

    fn cfg(network: &str) -> FaucetConfig {
        FaucetConfig { network: network.into(), node_endpoint: "http://localhost:8080".into(), distribution_amount: 1_000_000_000, cooldown_seconds: 3600, pow_difficulty: 4, key_file: None }
    }

    #[test]
    fn faucet_rejects_mainnet() {
        assert!(Faucet::new(cfg("mainnet")).is_err());
    }

    #[test]
    fn faucet_accepts_testnet() {
        let f = Faucet::new(cfg("testnet")).unwrap();
        assert_eq!(f.config().network, "testnet");
    }

    #[test]
    fn faucet_accepts_devnet() {
        assert!(Faucet::new(cfg("devnet")).is_ok());
    }

    #[test]
    fn faucet_status_stores_fields() {
        let status = FaucetStatus {
            network: "testnet".into(),
            balance: FaucetBalance { available: Amount::from_nano(1_000_000) },
            requests_served: 42,
            cooldown_seconds: 3600,
        };
        assert_eq!(status.requests_served, 42);
        assert_eq!(status.balance.available.as_nano(), 1_000_000u128);
    }
}
