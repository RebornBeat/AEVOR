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
