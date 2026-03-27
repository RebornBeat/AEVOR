//! Secondary indices for fast querying.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::{Address, ObjectId};
use aevor_core::privacy::PrivacyLevel;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexQuery {
    pub index_type: String,
    pub key: Vec<u8>,
    pub limit: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexResult {
    pub object_ids: Vec<ObjectId>,
    pub total: usize,
}

pub struct OwnerIndex(std::collections::HashMap<[u8; 32], Vec<ObjectId>>);
impl OwnerIndex {
    pub fn new() -> Self { Self(std::collections::HashMap::new()) }
    pub fn add(&mut self, owner: Address, id: ObjectId) {
        self.0.entry(owner.0).or_default().push(id);
    }
    pub fn get(&self, owner: &Address) -> &[ObjectId] {
        self.0.get(&owner.0).map_or(&[], Vec::as_slice)
    }
}
impl Default for OwnerIndex { fn default() -> Self { Self::new() } }

pub struct TypeIndex(std::collections::HashMap<String, Vec<ObjectId>>);
impl TypeIndex {
    pub fn new() -> Self { Self(std::collections::HashMap::new()) }
    pub fn add(&mut self, type_name: String, id: ObjectId) {
        self.0.entry(type_name).or_default().push(id);
    }
}
impl Default for TypeIndex { fn default() -> Self { Self::new() } }

pub struct PrivacyIndex(std::collections::HashMap<u8, Vec<ObjectId>>);
impl PrivacyIndex {
    pub fn new() -> Self { Self(std::collections::HashMap::new()) }
    pub fn add(&mut self, level: PrivacyLevel, id: ObjectId) {
        self.0.entry(level as u8).or_default().push(id);
    }
}
impl Default for PrivacyIndex { fn default() -> Self { Self::new() } }

pub struct SecondaryIndex {
    pub owner: OwnerIndex,
    pub type_: TypeIndex,
    pub privacy: PrivacyIndex,
}

pub struct IndexManager {
    indices: SecondaryIndex,
}

impl IndexManager {
    /// Create a new empty index manager.
    pub fn new() -> Self {
        Self {
            indices: SecondaryIndex {
                owner: OwnerIndex::new(),
                type_: TypeIndex::new(),
                privacy: PrivacyIndex::new(),
            }
        }
    }

    /// Access the secondary indices directly.
    pub fn indices(&self) -> &SecondaryIndex { &self.indices }

    /// Access the secondary indices mutably.
    pub fn indices_mut(&mut self) -> &mut SecondaryIndex { &mut self.indices }

    /// Index an object under its owner address.
    pub fn index_by_owner(&mut self, owner: aevor_core::primitives::Address, id: aevor_core::primitives::ObjectId) {
        self.indices.owner.add(owner, id);
    }

    /// Index an object under its type name.
    pub fn index_by_type(&mut self, type_name: String, id: aevor_core::primitives::ObjectId) {
        self.indices.type_.add(type_name, id);
    }

    /// Retrieve all object IDs for a given owner.
    pub fn objects_for_owner(&self, owner: &aevor_core::primitives::Address) -> &[aevor_core::primitives::ObjectId] {
        self.indices.owner.get(owner)
    }
}

impl Default for IndexManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{Address, Hash256, ObjectId};
    use aevor_core::privacy::PrivacyLevel;

    fn addr(n: u8) -> Address { Address([n; 32]) }
    fn obj(n: u8) -> ObjectId { ObjectId(Hash256([n; 32])) }

    #[test]
    fn owner_index_add_and_get() {
        let mut idx = OwnerIndex::new();
        idx.add(addr(1), obj(10));
        idx.add(addr(1), obj(11));
        let owned = idx.get(&addr(1));
        assert_eq!(owned.len(), 2);
        assert!(owned.contains(&obj(10)));
        assert!(owned.contains(&obj(11)));
    }

    #[test]
    fn owner_index_get_missing_returns_empty_slice() {
        let idx = OwnerIndex::default();
        assert!(idx.get(&addr(99)).is_empty());
    }

    #[test]
    fn type_index_add_groups_by_type() {
        let mut idx = TypeIndex::new();
        idx.add("Coin".into(), obj(1));
        idx.add("Coin".into(), obj(2));
        idx.add("NFT".into(), obj(3));
        // Internal state: 2 Coin entries, 1 NFT
        assert_eq!(idx.0.get("Coin").unwrap().len(), 2);
        assert_eq!(idx.0.get("NFT").unwrap().len(), 1);
    }

    #[test]
    fn privacy_index_groups_by_level() {
        let mut idx = PrivacyIndex::new();
        idx.add(PrivacyLevel::Public, obj(1));
        idx.add(PrivacyLevel::Private, obj(2));
        idx.add(PrivacyLevel::Public, obj(3));
        assert_eq!(idx.0.get(&(PrivacyLevel::Public as u8)).unwrap().len(), 2);
        assert_eq!(idx.0.get(&(PrivacyLevel::Private as u8)).unwrap().len(), 1);
    }

    #[test]
    fn index_manager_index_by_owner_and_retrieve() {
        let mut mgr = IndexManager::new();
        mgr.index_by_owner(addr(5), obj(10));
        mgr.index_by_owner(addr(5), obj(11));
        let owned = mgr.objects_for_owner(&addr(5));
        assert_eq!(owned.len(), 2);
    }

    #[test]
    fn index_manager_objects_for_unknown_owner_is_empty() {
        let mgr = IndexManager::default();
        assert!(mgr.objects_for_owner(&addr(42)).is_empty());
    }

    #[test]
    fn index_manager_index_by_type() {
        let mut mgr = IndexManager::new();
        mgr.index_by_type("Token".into(), obj(1));
        mgr.index_by_type("Token".into(), obj(2));
        assert_eq!(mgr.indices().type_.0.get("Token").unwrap().len(), 2);
    }
}
