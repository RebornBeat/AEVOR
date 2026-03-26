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
