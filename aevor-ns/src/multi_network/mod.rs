//! Multi-network domain policies.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiNetworkDomain { pub name: String, pub networks: Vec<String> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkDomainPolicy { pub network: String, pub allow_public: bool }
pub struct CrossNetworkResolution;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubnetDomain { pub subnet_id: String, pub domain_suffix: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridDomainConfig { pub public_suffix: String, pub private_suffix: String }
