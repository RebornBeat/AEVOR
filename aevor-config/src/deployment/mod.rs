//! Deployment mode and subnet configuration.

use serde::{Deserialize, Serialize};

/// Deployment mode and subnet configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Deployment mode.
    pub mode: DeploymentMode,
    /// Subnet deployment configuration (if applicable).
    pub subnet: Option<SubnetDeploymentConfig>,
    /// Hybrid deployment configuration (public + private).
    pub hybrid: Option<HybridDeploymentConfig>,
    /// Enterprise subnet configuration.
    pub enterprise: Option<EnterpriseSubnetConfig>,
    /// Data directory path.
    pub data_dir: std::path::PathBuf,
    /// Log directory path.
    pub log_dir: std::path::PathBuf,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            mode: DeploymentMode::PublicMainnet,
            subnet: None,
            hybrid: None,
            enterprise: None,
            data_dir: default_data_dir(),
            log_dir: default_log_dir(),
        }
    }
}

fn default_data_dir() -> std::path::PathBuf {
    let mut p = dirs::home_dir().unwrap_or_default();
    p.push(".aevor");
    p.push("data");
    p
}

fn default_log_dir() -> std::path::PathBuf {
    let mut p = dirs::home_dir().unwrap_or_default();
    p.push(".aevor");
    p.push("logs");
    p
}

/// Node deployment mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum DeploymentMode {
    /// Public mainnet (open participation, fees enabled).
    #[default]
    PublicMainnet,
    /// Public testnet (open participation, no real value).
    PublicTestnet,
    /// Public devnet (development and testing).
    PublicDevnet,
    /// Permissioned enterprise subnet.
    EnterpriseSubnet,
    /// Hybrid (partially public, partially private).
    Hybrid,
    /// Standalone research node (isolated from all networks).
    Research,
}

impl DeploymentMode {
    /// Returns `true` if this mode connects to a public network.
    pub fn is_public(&self) -> bool {
        matches!(self, Self::PublicMainnet | Self::PublicTestnet | Self::PublicDevnet | Self::Hybrid)
    }

    /// Returns `true` if this is a production deployment.
    pub fn is_production(&self) -> bool {
        matches!(self, Self::PublicMainnet | Self::EnterpriseSubnet)
    }

    /// Returns `true` if faucet should be enabled.
    pub fn enables_faucet(&self) -> bool {
        matches!(self, Self::PublicTestnet | Self::PublicDevnet)
    }
}

/// Configuration for subnet deployments.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubnetDeploymentConfig {
    /// Subnet identifier (hex hash or name).
    pub subnet_id: String,
    /// Human-readable name.
    pub name: String,
    /// Whether this subnet is permissioned.
    pub permissioned: bool,
    /// Permitted participant addresses.
    pub permitted_participants: Vec<String>,
    /// Whether fees are enabled on this subnet.
    pub fees_enabled: bool,
    /// Custom fee policy for this subnet.
    pub fee_policy: Option<String>,
    /// Privacy level enforced on this subnet.
    pub enforced_privacy_level: Option<String>,
}

/// Configuration for hybrid deployments (public + private components).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridDeploymentConfig {
    /// Public network participation configuration.
    pub public_participation: bool,
    /// Private component subnet ID.
    pub private_subnet_id: String,
    /// Data partition policy (what stays private).
    pub partition_policy: String,
    /// Whether to bridge public and private components.
    pub enable_bridge: bool,
}

/// Configuration for enterprise subnet deployments.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnterpriseSubnetConfig {
    /// Organization identifier.
    pub organization_id: String,
    /// Organization name.
    pub organization_name: String,
    /// Compliance requirements.
    pub compliance_requirements: Vec<String>,
    /// Permitted jurisdictions (for compliance).
    pub permitted_jurisdictions: Vec<String>,
    /// Whether audit logging is required.
    pub require_audit_log: bool,
    /// Whether all validators must be KYC'd.
    pub require_kyc_validators: bool,
    /// Data retention policy in days (0 = indefinite).
    pub data_retention_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_config_default_is_mainnet() {
        let cfg = DeploymentConfig::default();
        assert_eq!(cfg.mode, DeploymentMode::PublicMainnet);
        assert!(cfg.subnet.is_none());
        assert!(cfg.hybrid.is_none());
        assert!(cfg.enterprise.is_none());
    }

    #[test]
    fn default_data_dir_contains_aevor() {
        let cfg = DeploymentConfig::default();
        assert!(cfg.data_dir.to_string_lossy().contains(".aevor"));
        assert!(cfg.data_dir.to_string_lossy().contains("data"));
    }

    #[test]
    fn default_log_dir_contains_aevor_logs() {
        let cfg = DeploymentConfig::default();
        assert!(cfg.log_dir.to_string_lossy().contains(".aevor"));
        assert!(cfg.log_dir.to_string_lossy().contains("logs"));
    }

    #[test]
    fn deployment_mode_is_public() {
        assert!(DeploymentMode::PublicMainnet.is_public());
        assert!(DeploymentMode::PublicTestnet.is_public());
        assert!(DeploymentMode::PublicDevnet.is_public());
        assert!(DeploymentMode::Hybrid.is_public());
        assert!(!DeploymentMode::EnterpriseSubnet.is_public());
        assert!(!DeploymentMode::Research.is_public());
    }

    #[test]
    fn deployment_mode_is_production() {
        assert!(DeploymentMode::PublicMainnet.is_production());
        assert!(DeploymentMode::EnterpriseSubnet.is_production());
        assert!(!DeploymentMode::PublicTestnet.is_production());
        assert!(!DeploymentMode::Research.is_production());
    }

    #[test]
    fn deployment_mode_enables_faucet_only_for_test_and_dev() {
        assert!(DeploymentMode::PublicTestnet.enables_faucet());
        assert!(DeploymentMode::PublicDevnet.enables_faucet());
        assert!(!DeploymentMode::PublicMainnet.enables_faucet());
        assert!(!DeploymentMode::EnterpriseSubnet.enables_faucet());
    }

    #[test]
    fn hybrid_deployment_config_fields() {
        let h = HybridDeploymentConfig {
            public_participation: true,
            private_subnet_id: "subnet-abc".into(),
            partition_policy: "pii-private".into(),
            enable_bridge: true,
        };
        assert!(h.public_participation);
        assert!(h.enable_bridge);
        assert_eq!(h.private_subnet_id, "subnet-abc");
    }

    #[test]
    fn enterprise_config_audit_and_kyc_defaults() {
        let e = EnterpriseSubnetConfig {
            organization_id: "org-1".into(),
            organization_name: "ACME Corp".into(),
            compliance_requirements: vec!["SOC2".into()],
            permitted_jurisdictions: vec!["US".into()],
            require_audit_log: true,
            require_kyc_validators: true,
            data_retention_days: 365,
        };
        assert!(e.require_audit_log);
        assert!(e.require_kyc_validators);
        assert_eq!(e.data_retention_days, 365);
        assert_eq!(e.compliance_requirements, vec!["SOC2"]);
    }
}
