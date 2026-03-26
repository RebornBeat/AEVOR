//! Default configuration factories for all deployment modes.

use crate::{
    AevorConfig,
    consensus::ConsensusConfig,
    deployment::{DeploymentConfig, DeploymentMode},
    economics::EconomicsConfig,
    network::{GenesisConfig, NetworkConfig, NetworkType},
    privacy::PrivacyConfig,
    tee::{AttestationMode, TeeAttestationConfig, TeeConfig},
};
use aevor_core::primitives::ChainId;

/// Create default configuration for mainnet.
pub fn mainnet_defaults() -> AevorConfig {
    AevorConfig {
        network: NetworkConfig {
            chain_id: ChainId::MAINNET,
            network_type: NetworkType::Mainnet,
            genesis: GenesisConfig {
                protocol_version: "1.0.0".into(),
                initial_supply_nano: 1_000_000_000 * 1_000_000_000u128,
                ..Default::default()
            },
            max_peers: 50,
            ..Default::default()
        },
        tee: TeeConfig {
            required_for_validator: true,
            fail_if_unavailable: false,
            attestation: TeeAttestationConfig {
                require_production: true,
                mode: AttestationMode::Local,
                ..Default::default()
            },
            ..Default::default()
        },
        privacy: PrivacyConfig {
            strict_enforcement: true,
            ..Default::default()
        },
        consensus: ConsensusConfig {
            min_validator_stake: 100_000 * 1_000_000_000u128,
            max_validators: 256,
            blocks_per_epoch: 10_000,
            ..Default::default()
        },
        economics: EconomicsConfig {
            initial_supply_nano: 1_000_000_000 * 1_000_000_000u128,
            annual_inflation_bps: 500,
            ..Default::default()
        },
        deployment: DeploymentConfig {
            mode: DeploymentMode::PublicMainnet,
            ..Default::default()
        },
    }
}

/// Create default configuration for testnet.
pub fn testnet_defaults() -> AevorConfig {
    let mut config = mainnet_defaults();
    config.network.chain_id = ChainId::TESTNET;
    config.network.network_type = NetworkType::Testnet;
    config.tee.attestation.require_production = false;
    config.tee.attestation.mode = AttestationMode::Simulation;
    config.consensus.min_validator_stake = 1_000 * 1_000_000_000u128;
    config.consensus.max_validators = 64;
    config.deployment.mode = DeploymentMode::PublicTestnet;
    config
}

/// Create default configuration for devnet.
pub fn devnet_defaults() -> AevorConfig {
    let mut config = testnet_defaults();
    config.network.chain_id = ChainId::DEVNET;
    config.network.network_type = NetworkType::Devnet;
    config.consensus.min_validator_stake = 1_000_000_000u128; // 1 AEVOR
    config.consensus.max_validators = 4;
    config.consensus.blocks_per_epoch = 100;
    config.deployment.mode = DeploymentMode::PublicDevnet;
    config
}

/// Create default configuration for an enterprise permissioned subnet.
pub fn enterprise_subnet_defaults() -> AevorConfig {
    let mut config = mainnet_defaults();
    config.network.network_type = NetworkType::EnterpriseSubnet;
    config.consensus.min_validator_stake = 0; // Permissioned — no stake needed
    config.economics.fee.enabled = false;
    config.deployment.mode = DeploymentMode::EnterpriseSubnet;
    config
}
