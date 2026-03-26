//! TEE service discovery via DNS.

use serde::{Deserialize, Serialize};
use aevor_core::tee::{TeePlatform, TeeServiceType};
use aevor_core::primitives::ValidatorId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeServiceRecord {
    pub service_type: TeeServiceType, pub platform: TeePlatform,
    pub endpoint: String, pub validator: ValidatorId,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeEndpointRecord { pub endpoint: String, pub platform: TeePlatform }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceCapabilityRecord { pub capability: String, pub version: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryQuery { pub service_type: TeeServiceType, pub preferred_platform: Option<TeePlatform> }

pub struct ServiceDiscoveryDns { records: Vec<TeeServiceRecord> }
impl ServiceDiscoveryDns {
    pub fn new() -> Self { Self { records: Vec::new() } }
    pub fn register(&mut self, r: TeeServiceRecord) { self.records.push(r); }
    pub fn find(&self, query: &DiscoveryQuery) -> Vec<&TeeServiceRecord> {
        self.records.iter().filter(|r| r.service_type == query.service_type).collect()
    }
}
impl Default for ServiceDiscoveryDns { fn default() -> Self { Self::new() } }
