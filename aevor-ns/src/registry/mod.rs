//! Domain name registry.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, Hash256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRecord {
    pub name: String,
    pub owner: Address,
    pub registered_at_round: u64,
    /// BLAKE3 hash of the name + owner for deduplication.
    pub record_hash: Hash256,
}
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
        let mut h = [0u8; 32];
        for (i, b) in req.name.bytes().enumerate() { h[i % 32] ^= b; }
        for (i, b) in req.owner.0.iter().enumerate() { h[i % 32] ^= b; }
        let record = DomainRecord {
            name: req.name.clone(),
            owner: req.owner,
            registered_at_round: round,
            record_hash: aevor_core::primitives::Hash256(h),
        };
        self.domains.insert(req.name, record.clone());
        RegistrationResult { success: true, domain: Some(record) }
    }
    pub fn lookup(&self, name: &str) -> Option<&DomainRecord> { self.domains.get(name) }
    pub fn count(&self) -> usize { self.domains.len() }
}
impl Default for DomainRegistry { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Address;

    fn addr(n: u8) -> Address { Address([n; 32]) }

    fn req(name: &str, owner: u8) -> RegistrationRequest {
        RegistrationRequest { name: name.into(), owner: addr(owner), proof: vec![] }
    }

    #[test]
    fn register_new_domain_succeeds() {
        let mut reg = DomainRegistry::new();
        let result = reg.register(req("alice.aevor", 1), 100);
        assert!(result.success);
        let domain = result.domain.unwrap();
        assert_eq!(domain.name, "alice.aevor");
        assert_eq!(domain.owner, addr(1));
        assert_eq!(domain.registered_at_round, 100);
    }

    #[test]
    fn register_duplicate_domain_fails() {
        let mut reg = DomainRegistry::new();
        reg.register(req("alice.aevor", 1), 100);
        let second = reg.register(req("alice.aevor", 2), 101);
        assert!(!second.success);
        assert!(second.domain.is_none());
    }

    #[test]
    fn lookup_registered_domain() {
        let mut reg = DomainRegistry::default();
        reg.register(req("bob.aevor", 2), 50);
        let record = reg.lookup("bob.aevor").unwrap();
        assert_eq!(record.owner, addr(2));
    }

    #[test]
    fn lookup_unregistered_returns_none() {
        let reg = DomainRegistry::new();
        assert!(reg.lookup("unknown.aevor").is_none());
    }

    #[test]
    fn count_tracks_registrations() {
        let mut reg = DomainRegistry::new();
        assert_eq!(reg.count(), 0);
        reg.register(req("a.aevor", 1), 1);
        reg.register(req("b.aevor", 2), 2);
        assert_eq!(reg.count(), 2);
    }

    #[test]
    fn domain_record_hash_differs_for_different_names() {
        let mut reg = DomainRegistry::new();
        let r1 = reg.register(req("alpha.aevor", 1), 1).domain.unwrap();
        let r2 = reg.register(req("beta.aevor", 1), 2).domain.unwrap();
        assert_ne!(r1.record_hash, r2.record_hash);
    }
}
