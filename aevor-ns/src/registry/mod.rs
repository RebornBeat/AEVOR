//! Domain name registry.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Hash256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRecord { pub name: String, pub owner: Address, pub registered_at_round: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationRequest { pub name: String, pub owner: Address, pub proof: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationResult { pub success: bool, pub domain: Option<DomainRecord> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainTransfer { pub name: String, pub from: Address, pub to: Address }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRenewal { pub name: String, pub extend_by_rounds: u64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainOwnership { pub name: String, pub owner: Address, pub proof: Vec<u8> }

pub struct DomainRegistry { domains: std::collections::HashMap<String, DomainRecord> }
impl DomainRegistry {
    pub fn new() -> Self { Self { domains: std::collections::HashMap::new() } }
    pub fn register(&mut self, req: RegistrationRequest, round: u64) -> RegistrationResult {
        if self.domains.contains_key(&req.name) {
            return RegistrationResult { success: false, domain: None };
        }
        let record = DomainRecord { name: req.name.clone(), owner: req.owner, registered_at_round: round };
        self.domains.insert(req.name, record.clone());
        RegistrationResult { success: true, domain: Some(record) }
    }
    pub fn lookup(&self, name: &str) -> Option<&DomainRecord> { self.domains.get(name) }
    pub fn count(&self) -> usize { self.domains.len() }
}
impl Default for DomainRegistry { fn default() -> Self { Self::new() } }
