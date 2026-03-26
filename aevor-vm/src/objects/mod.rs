//! VM object model: runtime representation of blockchain objects.
//!
//! Each object has an owner, a privacy level, and typed data.
//! The VM tracks object versions to detect write-write conflicts
//! during parallel execution.

use serde::{Deserialize, Serialize};

/// The type of a VM object, expressed as a Move-style type tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectType {
    /// Module address (hex-encoded).
    pub address: String,
    /// Module name.
    pub module: String,
    /// Struct name within the module.
    pub name: String,
}

impl ObjectType {
    /// Create a new object type.
    pub fn new(address: impl Into<String>, module: impl Into<String>, name: impl Into<String>) -> Self {
        Self { address: address.into(), module: module.into(), name: name.into() }
    }

    /// Returns the fully qualified type string `address::module::name`.
    pub fn qualified_name(&self) -> String {
        format!("{}::{}::{}", self.address, self.module, self.name)
    }
}

/// A resource value stored inside a VM object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceValue {
    /// BCS-serialized bytes of the resource.
    pub bytes: Vec<u8>,
    /// Type of this resource.
    pub type_: ObjectType,
}

impl ResourceValue {
    /// Create a new resource value.
    pub fn new(type_: ObjectType, bytes: Vec<u8>) -> Self {
        Self { bytes, type_ }
    }

    /// Size of this resource in bytes.
    pub fn size(&self) -> usize { self.bytes.len() }
}

/// A VM-layer object with version tracking.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VmObject {
    /// Unique identifier (hex-encoded Hash256).
    pub id: String,
    /// Owner address (hex-encoded).
    pub owner: String,
    /// The resource payload.
    pub resource: ResourceValue,
    /// Monotonically increasing write version.
    pub version: u64,
    /// Whether this object is shared (accessible to all callers).
    pub shared: bool,
}

impl VmObject {
    /// Create a new VM object.
    pub fn new(id: String, owner: String, resource: ResourceValue) -> Self {
        Self { id, owner, resource, version: 0, shared: false }
    }

    /// Advance the version after a write.
    pub fn increment_version(&mut self) { self.version += 1; }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_type_qualified_name() {
        let t = ObjectType::new("0x1", "coin", "Coin");
        assert_eq!(t.qualified_name(), "0x1::coin::Coin");
    }

    #[test]
    fn resource_size_matches_bytes() {
        let t = ObjectType::new("0x1", "coin", "Coin");
        let r = ResourceValue::new(t, vec![1, 2, 3, 4]);
        assert_eq!(r.size(), 4);
    }

    #[test]
    fn vm_object_version_increments() {
        let t = ObjectType::new("0x1", "a", "B");
        let r = ResourceValue::new(t, vec![]);
        let mut obj = VmObject::new("id".into(), "owner".into(), r);
        assert_eq!(obj.version, 0);
        obj.increment_version();
        assert_eq!(obj.version, 1);
    }
}
