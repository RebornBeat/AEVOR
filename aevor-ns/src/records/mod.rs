//! DNS record types.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordType { A, Aaaa, Mx, Txt, Cname, Ns, Ptr, Srv, TeeService }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ARecord { pub name: String, pub ipv4: std::net::Ipv4Addr, pub ttl: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AaaaRecord { pub name: String, pub ipv6: std::net::Ipv6Addr, pub ttl: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MxRecord { pub name: String, pub exchange: String, pub priority: u16, pub ttl: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxtRecord { pub name: String, pub text: Vec<String>, pub ttl: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CnameRecord { pub name: String, pub canonical: String, pub ttl: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NsRecord { pub name: String, pub nameserver: String, pub ttl: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PtrRecord { pub name: String, pub ptr: String, pub ttl: u32 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SrvRecord { pub name: String, pub target: String, pub port: u16, pub priority: u16, pub weight: u16, pub ttl: u32 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DnsRecord { A(ARecord), Aaaa(AaaaRecord), Mx(MxRecord), Txt(TxtRecord), Cname(CnameRecord), Ns(NsRecord), Ptr(PtrRecord), Srv(SrvRecord) }

impl DnsRecord {
    pub fn record_type(&self) -> RecordType {
        match self { Self::A(_) => RecordType::A, Self::Aaaa(_) => RecordType::Aaaa, Self::Mx(_) => RecordType::Mx, Self::Txt(_) => RecordType::Txt, Self::Cname(_) => RecordType::Cname, Self::Ns(_) => RecordType::Ns, Self::Ptr(_) => RecordType::Ptr, Self::Srv(_) => RecordType::Srv }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsRecordSet { pub records: Vec<DnsRecord> }
impl DnsRecordSet {
    pub fn new() -> Self { Self { records: Vec::new() } }
    pub fn add(&mut self, r: DnsRecord) { self.records.push(r); }
    pub fn of_type(&self, t: RecordType) -> Vec<&DnsRecord> {
        self.records.iter().filter(|r| r.record_type() == t).collect()
    }
}
impl Default for DnsRecordSet { fn default() -> Self { Self::new() } }
