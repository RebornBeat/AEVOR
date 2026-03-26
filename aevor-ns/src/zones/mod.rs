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
