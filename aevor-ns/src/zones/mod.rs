//! DNS zone management.

use serde::{Deserialize, Serialize};
use crate::records::DnsRecordSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SoaRecord { pub mname: String, pub rname: String, pub serial: u32, pub refresh: u32, pub retry: u32, pub expire: u32, pub minimum: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneData { pub origin: String, pub soa: SoaRecord, pub records: DnsRecordSet }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneTransfer { pub zone: String, pub records: DnsRecordSet }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneDelegate { pub delegated: String, pub ns: Vec<String> }

pub struct AuthoritativeZone { data: ZoneData }
impl AuthoritativeZone {
    pub fn new(data: ZoneData) -> Self { Self { data } }
    pub fn origin(&self) -> &str { &self.data.origin }
}

pub struct Zone { pub name: String, pub authoritative: bool }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::DnsRecordSet;

    fn soa() -> SoaRecord {
        SoaRecord { mname: "ns1.aevor.".into(), rname: "admin.aevor.".into(), serial: 2024010101, refresh: 3600, retry: 900, expire: 604800, minimum: 300 }
    }

    #[test]
    fn authoritative_zone_origin() {
        let zone = AuthoritativeZone::new(ZoneData { origin: "aevor.".into(), soa: soa(), records: DnsRecordSet::default() });
        assert_eq!(zone.origin(), "aevor.");
    }

    #[test]
    fn zone_delegate_stores_ns_records() {
        let d = ZoneDelegate { delegated: "sub.aevor.".into(), ns: vec!["ns1.aevor.".into(), "ns2.aevor.".into()] };
        assert_eq!(d.ns.len(), 2);
    }

    #[test]
    fn soa_record_stores_all_timing_fields() {
        let s = soa();
        assert!(s.refresh > 0);
        assert!(s.expire > s.refresh);
    }
}
