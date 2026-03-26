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
        self.0.get(&owner.0).map(Vec::as_slice).unwrap_or(&[])
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
