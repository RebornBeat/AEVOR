//! Move runtime adapter for AEVOR VM.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Address;

/// A handle to a running Move runtime instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeHandle { pub id: aevor_core::primitives::Hash256 }

/// A handle to an active contract execution session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionHandle {
    pub session_id: aevor_core::primitives::Hash256,
    pub active: bool,
    /// The contract address being executed.
    pub contract: Address,
}

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
        format!("{module}::{function}")
    }
}

pub struct MoveRuntimeAdapter { loader: ModuleLoader }
impl MoveRuntimeAdapter {
    pub fn new() -> Self { Self { loader: ModuleLoader::new() } }
    pub fn loader(&mut self) -> &mut ModuleLoader { &mut self.loader }
}
impl Default for MoveRuntimeAdapter { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_loader_stores_and_retrieves() {
        let mut loader = ModuleLoader::new();
        loader.load("my_module".into(), vec![0xDE, 0xAD]);
        let bytecode = loader.get("my_module").unwrap();
        assert_eq!(bytecode, &vec![0xDE, 0xAD]);
    }

    #[test]
    fn module_loader_count_tracks_entries() {
        let mut loader = ModuleLoader::new();
        assert_eq!(loader.count(), 0);
        loader.load("a".into(), vec![1]);
        loader.load("b".into(), vec![2]);
        assert_eq!(loader.count(), 2);
    }

    #[test]
    fn module_loader_returns_none_for_missing() {
        let loader = ModuleLoader::default();
        assert!(loader.get("nonexistent").is_none());
    }

    #[test]
    fn function_dispatch_formats_correctly() {
        let result = FunctionDispatch::dispatch("my_module", "transfer");
        assert_eq!(result, "my_module::transfer");
    }

    #[test]
    fn function_dispatch_handles_empty_strings() {
        let result = FunctionDispatch::dispatch("", "fn");
        assert_eq!(result, "::fn");
    }

    #[test]
    fn runtime_adapter_loader_accessible() {
        let mut adapter = MoveRuntimeAdapter::new();
        adapter.loader().load("test".into(), vec![42]);
        assert_eq!(adapter.loader().count(), 1);
    }
}
