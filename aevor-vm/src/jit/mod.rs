//! JIT compilation for hot contract paths.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::Hash256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompiledFunction { pub name: String, pub native_size_bytes: usize, pub hash: Hash256 }

pub struct JitCache { functions: std::collections::HashMap<[u8; 32], CompiledFunction> }
impl JitCache {
    pub fn new() -> Self { Self { functions: std::collections::HashMap::new() } }
    pub fn insert(&mut self, key: Hash256, f: CompiledFunction) { self.functions.insert(key.0, f); }
    pub fn get(&self, key: &Hash256) -> Option<&CompiledFunction> { self.functions.get(&key.0) }
    pub fn count(&self) -> usize { self.functions.len() }
}
impl Default for JitCache { fn default() -> Self { Self::new() } }

pub struct WarmupTracker { call_counts: std::collections::HashMap<[u8; 32], u64>, threshold: u64 }
impl WarmupTracker {
    pub fn new(threshold: u64) -> Self { Self { call_counts: std::collections::HashMap::new(), threshold } }
    pub fn record_call(&mut self, func_hash: &Hash256) -> bool {
        let count = self.call_counts.entry(func_hash.0).or_insert(0);
        *count += 1;
        *count >= self.threshold
    }
}

pub struct HotPathOptimizer { cache: JitCache }
impl HotPathOptimizer {
    pub fn new() -> Self { Self { cache: JitCache::new() } }
    pub fn is_compiled(&self, key: &Hash256) -> bool { self.cache.get(key).is_some() }
}
impl Default for HotPathOptimizer { fn default() -> Self { Self::new() } }

pub struct JitCompiler { cache: JitCache }
impl JitCompiler {
    pub fn new() -> Self { Self { cache: JitCache::new() } }
    pub fn cache(&self) -> &JitCache { &self.cache }
}
impl Default for JitCompiler { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::Hash256;

    fn fhash(n: u8) -> Hash256 { Hash256([n; 32]) }

    fn compiled(name: &str) -> CompiledFunction {
        CompiledFunction { name: name.into(), native_size_bytes: 1024, hash: Hash256::ZERO }
    }

    #[test]
    fn jit_cache_insert_and_get() {
        let mut cache = JitCache::new();
        cache.insert(fhash(1), compiled("transfer"));
        let f = cache.get(&fhash(1)).unwrap();
        assert_eq!(f.name, "transfer");
        assert_eq!(cache.count(), 1);
    }

    #[test]
    fn jit_cache_get_missing_returns_none() {
        let cache = JitCache::default();
        assert!(cache.get(&fhash(99)).is_none());
    }

    #[test]
    fn warmup_tracker_triggers_at_threshold() {
        let mut tracker = WarmupTracker::new(3);
        let h = fhash(1);
        assert!(!tracker.record_call(&h)); // 1
        assert!(!tracker.record_call(&h)); // 2
        assert!(tracker.record_call(&h));  // 3 — triggers JIT
    }

    #[test]
    fn hot_path_optimizer_compiled_after_insert() {
        let mut opt = HotPathOptimizer::new();
        assert!(!opt.is_compiled(&fhash(1)));
        opt.cache.insert(fhash(1), compiled("hot_fn"));
        assert!(opt.is_compiled(&fhash(1)));
    }
}
