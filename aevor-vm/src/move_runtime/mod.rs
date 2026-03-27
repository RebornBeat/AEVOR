//! Move language runtime with AEVOR extensions.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveModule {
    pub address: aevor_core::primitives::Address,
    pub name: String,
    pub bytecode: Vec<u8>,
    pub metadata: ModuleMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleMetadata {
    pub version: u32,
    pub dependencies: Vec<String>,
    pub abilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoveFunction {
    pub module: String,
    pub name: String,
    pub parameters: Vec<MoveType>,
    pub return_types: Vec<MoveType>,
    pub is_public: bool,
    pub is_entry: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveType {
    Bool, U8, U64, U128, Address, Signer,
    Vector(Box<MoveType>),
    Struct { module: String, name: String },
    Reference(Box<MoveType>),
    MutableReference(Box<MoveType>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MoveValue {
    Bool(bool),
    U8(u8),
    U64(u64),
    U128(u128),
    Address(aevor_core::primitives::Address),
    Vector(Vec<MoveValue>),
    Struct(Vec<(String, MoveValue)>),
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ResourceTable {
    pub resources: std::collections::HashMap<String, Vec<u8>>,
}

impl ResourceTable {
    pub fn new() -> Self { Self::default() }
    pub fn insert(&mut self, type_tag: String, data: Vec<u8>) {
        self.resources.insert(type_tag, data);
    }
    pub fn get(&self, type_tag: &str) -> Option<&Vec<u8>> { self.resources.get(type_tag) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeParameters {
    pub params: Vec<MoveType>,
    pub constraints: Vec<String>,
}

pub struct MoveRuntime {
    modules: std::collections::HashMap<String, MoveModule>,
}

impl MoveRuntime {
    pub fn new() -> Self { Self { modules: std::collections::HashMap::new() } }
    pub fn load_module(&mut self, module: MoveModule) { self.modules.insert(module.name.clone(), module); }
    pub fn get_module(&self, name: &str) -> Option<&MoveModule> { self.modules.get(name) }
    pub fn module_count(&self) -> usize { self.modules.len() }
}

impl Default for MoveRuntime {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Address;

    fn addr(n: u8) -> Address { Address([n; 32]) }

    fn make_module(name: &str) -> MoveModule {
        MoveModule {
            address: addr(1),
            name: name.into(),
            bytecode: vec![0xA1, 0xB2],
            metadata: ModuleMetadata {
                version: 1,
                dependencies: vec!["std".into()],
                abilities: vec!["copy".into(), "drop".into()],
            },
        }
    }

    #[test]
    fn move_runtime_load_and_get_module() {
        let mut rt = MoveRuntime::new();
        rt.load_module(make_module("MyToken"));
        assert_eq!(rt.module_count(), 1);
        let m = rt.get_module("MyToken").unwrap();
        assert_eq!(m.name, "MyToken");
    }

    #[test]
    fn move_runtime_get_missing_returns_none() {
        let rt = MoveRuntime::default();
        assert!(rt.get_module("NonExistent").is_none());
    }

    #[test]
    fn move_runtime_load_replaces_existing() {
        let mut rt = MoveRuntime::new();
        rt.load_module(make_module("Mod"));
        rt.load_module(make_module("Mod")); // reload
        assert_eq!(rt.module_count(), 1);
    }

    #[test]
    fn resource_table_insert_and_get() {
        let mut table = ResourceTable::new();
        table.insert("0x1::Coin::Coin".into(), vec![1, 2, 3]);
        let data = table.get("0x1::Coin::Coin").unwrap();
        assert_eq!(data, &vec![1, 2, 3]);
    }

    #[test]
    fn resource_table_get_missing_returns_none() {
        let table = ResourceTable::default();
        assert!(table.get("UnknownType").is_none());
    }

    #[test]
    fn move_type_vector_wraps_inner() {
        let inner = MoveType::U64;
        let vec_ty = MoveType::Vector(Box::new(inner.clone()));
        assert_eq!(vec_ty, MoveType::Vector(Box::new(MoveType::U64)));
    }

    #[test]
    fn move_value_variants_roundtrip() {
        let v_bool = MoveValue::Bool(true);
        let v_u64 = MoveValue::U64(42);
        let v_addr = MoveValue::Address(addr(5));
        // Just verify they construct without panicking
        assert!(matches!(v_bool, MoveValue::Bool(true)));
        assert!(matches!(v_u64, MoveValue::U64(42)));
        assert!(matches!(v_addr, MoveValue::Address(_)));
    }

    #[test]
    fn move_function_is_public_and_entry_flags() {
        let f = MoveFunction {
            module: "MyModule".into(),
            name: "transfer".into(),
            parameters: vec![MoveType::Address, MoveType::U64],
            return_types: vec![],
            is_public: true,
            is_entry: true,
        };
        assert!(f.is_public);
        assert!(f.is_entry);
        assert_eq!(f.parameters.len(), 2);
    }
}
