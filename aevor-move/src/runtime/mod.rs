//! Move runtime adapter for AEVOR VM.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Address;

#[derive(Clone, Debug)]
pub struct RuntimeHandle { pub id: aevor_core::primitives::Hash256 }
#[derive(Clone, Debug)]
pub struct ExecutionHandle { pub session_id: aevor_core::primitives::Hash256, pub active: bool }

pub struct ModuleLoader { modules: std::collections::HashMap<String, Vec<u8>> }
impl ModuleLoader {
    pub fn new() -> Self { Self { modules: std::collections::HashMap::new() } }
    pub fn load(&mut self, name: String, bytecode: Vec<u8>) { self.modules.insert(name, bytecode); }
    pub fn get(&self, name: &str) -> Option<&Vec<u8>> { self.modules.get(name) }
    pub fn count(&self) -> usize { self.modules.len() }
}
impl Default for ModuleLoader { fn default() -> Self { Self::new() } }

pub struct FunctionDispatch;
impl FunctionDispatch {
    pub fn dispatch(module: &str, function: &str) -> String {
        format!("{}::{}", module, function)
    }
}

pub struct MoveRuntimeAdapter { loader: ModuleLoader }
impl MoveRuntimeAdapter {
    pub fn new() -> Self { Self { loader: ModuleLoader::new() } }
    pub fn loader(&mut self) -> &mut ModuleLoader { &mut self.loader }
}
impl Default for MoveRuntimeAdapter { fn default() -> Self { Self::new() } }
