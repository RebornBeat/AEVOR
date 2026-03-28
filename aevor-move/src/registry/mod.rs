//! On-chain module registry.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Address;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum UpgradePolicy { Immutable, Compatible, Arbitrary }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleVersion { pub major: u32, pub minor: u32, pub patch: u32 }
impl std::fmt::Display for ModuleVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleMetadata { pub name: String, pub version: ModuleVersion, pub author: Address }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryEntry { pub address: Address, pub metadata: ModuleMetadata, pub policy: UpgradePolicy }

pub struct ModuleRegistry { entries: Vec<RegistryEntry> }
impl ModuleRegistry {
    pub fn new() -> Self { Self { entries: Vec::new() } }
    pub fn register(&mut self, entry: RegistryEntry) { self.entries.push(entry); }
    pub fn lookup(&self, addr: &Address) -> Option<&RegistryEntry> {
        self.entries.iter().find(|e| &e.address == addr)
    }
    pub fn count(&self) -> usize { self.entries.len() }
}
impl Default for ModuleRegistry { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Address;

    fn addr(n: u8) -> Address { Address([n; 32]) }

    fn entry(a: u8, name: &str) -> RegistryEntry {
        RegistryEntry {
            address: addr(a),
            metadata: ModuleMetadata { name: name.into(), version: ModuleVersion { major: 1, minor: 0, patch: 0 }, author: addr(0) },
            policy: UpgradePolicy::Compatible,
        }
    }

    #[test]
    fn module_version_display() {
        let v = ModuleVersion { major: 1, minor: 2, patch: 3 };
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn module_registry_register_and_lookup() {
        let mut reg = ModuleRegistry::new();
        reg.register(entry(1, "token"));
        let found = reg.lookup(&addr(1)).unwrap();
        assert_eq!(found.metadata.name, "token");
    }

    #[test]
    fn module_registry_lookup_missing_returns_none() {
        let reg = ModuleRegistry::default();
        assert!(reg.lookup(&addr(99)).is_none());
    }

    #[test]
    fn module_registry_count() {
        let mut reg = ModuleRegistry::new();
        reg.register(entry(1, "a"));
        reg.register(entry(2, "b"));
        assert_eq!(reg.count(), 2);
    }

    #[test]
    fn upgrade_policy_variants() {
        assert!(matches!(UpgradePolicy::Immutable, UpgradePolicy::Immutable));
        assert!(matches!(UpgradePolicy::Compatible, UpgradePolicy::Compatible));
        assert!(matches!(UpgradePolicy::Arbitrary, UpgradePolicy::Arbitrary));
    }
}
