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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::tee::{TeePlatform, TeeServiceType};
    use aevor_core::primitives::Hash256;

    fn record(stype: TeeServiceType, platform: TeePlatform) -> TeeServiceRecord {
        TeeServiceRecord { service_type: stype, platform, endpoint: "http://tee.example.com".into(), validator: Hash256::ZERO }
    }

    #[test]
    fn service_discovery_find_by_type() {
        let mut dns = ServiceDiscoveryDns::new();
        dns.register(record(TeeServiceType::Execution, TeePlatform::IntelSgx));
        dns.register(record(TeeServiceType::Attestation, TeePlatform::AmdSev));
        let q = DiscoveryQuery { service_type: TeeServiceType::Execution, preferred_platform: None };
        let found = dns.find(&q);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].platform, TeePlatform::IntelSgx);
    }

    #[test]
    fn service_discovery_empty_result() {
        let dns = ServiceDiscoveryDns::default();
        let q = DiscoveryQuery { service_type: TeeServiceType::Execution, preferred_platform: None };
        assert!(dns.find(&q).is_empty());
    }
}
