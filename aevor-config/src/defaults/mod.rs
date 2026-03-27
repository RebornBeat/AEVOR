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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::ChainId;
    use crate::deployment::DeploymentMode;
    use crate::network::NetworkType;
    use crate::tee::AttestationMode;

    #[test]
    fn mainnet_defaults_chain_id_and_mode() {
        let cfg = mainnet_defaults();
        assert_eq!(cfg.network.chain_id, ChainId::MAINNET);
        assert_eq!(cfg.network.network_type, NetworkType::Mainnet);
        assert_eq!(cfg.deployment.mode, DeploymentMode::PublicMainnet);
    }

    #[test]
    fn mainnet_defaults_requires_production_attestation() {
        let cfg = mainnet_defaults();
        assert!(cfg.tee.attestation.require_production);
        assert_eq!(cfg.tee.attestation.mode, AttestationMode::Local);
        assert!(cfg.tee.required_for_validator);
    }

    #[test]
    fn mainnet_defaults_validator_stake_is_nonzero() {
        let cfg = mainnet_defaults();
        assert!(cfg.consensus.min_validator_stake > 0);
        assert_eq!(cfg.consensus.max_validators, 256);
        assert_eq!(cfg.consensus.blocks_per_epoch, 10_000);
    }

    #[test]
    fn testnet_defaults_chain_id_and_mode() {
        let cfg = testnet_defaults();
        assert_eq!(cfg.network.chain_id, ChainId::TESTNET);
        assert_eq!(cfg.network.network_type, NetworkType::Testnet);
        assert_eq!(cfg.deployment.mode, DeploymentMode::PublicTestnet);
    }

    #[test]
    fn testnet_defaults_simulation_attestation_not_production() {
        let cfg = testnet_defaults();
        assert!(!cfg.tee.attestation.require_production);
        assert_eq!(cfg.tee.attestation.mode, AttestationMode::Simulation);
    }

    #[test]
    fn testnet_defaults_lower_stake_than_mainnet() {
        let mainnet = mainnet_defaults();
        let testnet = testnet_defaults();
        assert!(testnet.consensus.min_validator_stake < mainnet.consensus.min_validator_stake);
        assert!(testnet.consensus.max_validators < mainnet.consensus.max_validators);
    }

    #[test]
    fn devnet_defaults_lowest_stake_and_smallest_epoch() {
        let testnet = testnet_defaults();
        let devnet = devnet_defaults();
        assert_eq!(devnet.network.chain_id, ChainId::DEVNET);
        assert_eq!(devnet.deployment.mode, DeploymentMode::PublicDevnet);
        assert!(devnet.consensus.min_validator_stake < testnet.consensus.min_validator_stake);
        assert_eq!(devnet.consensus.max_validators, 4);
        assert_eq!(devnet.consensus.blocks_per_epoch, 100);
    }

    #[test]
    fn enterprise_defaults_no_fees_no_stake_requirement() {
        let cfg = enterprise_subnet_defaults();
        assert_eq!(cfg.network.network_type, NetworkType::EnterpriseSubnet);
        assert_eq!(cfg.deployment.mode, DeploymentMode::EnterpriseSubnet);
        assert_eq!(cfg.consensus.min_validator_stake, 0);
        assert!(!cfg.economics.fee.enabled);
    }
}
