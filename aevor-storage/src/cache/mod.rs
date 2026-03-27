//! Multi-layer storage cache.

use serde::{Deserialize, Serialize};
use aevor_core::primitives::ObjectId;
use aevor_core::storage::{StateRoot, StorageKey, StorageValue};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_objects: usize,
    pub max_memory_bytes: usize,
    pub ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { max_objects: 10_000, max_memory_bytes: 512 * 1024 * 1024, ttl_seconds: 60 }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub current_size: usize,
}

impl CacheMetrics {
    #[allow(clippy::cast_precision_loss)] // hit/miss counts: precision loss acceptable for metrics
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum CachePolicy { LRU, LFU, ARC }

pub struct HotObjectCache {
    data: std::collections::HashMap<Vec<u8>, StorageValue>,
    config: CacheConfig,
}

impl HotObjectCache {
    pub fn new(config: CacheConfig) -> Self { Self { data: std::collections::HashMap::new(), config } }
    pub fn get(&self, key: &StorageKey) -> Option<&StorageValue> { self.data.get(&key.0) }
    pub fn put(&mut self, key: StorageKey, value: StorageValue) {
        if self.data.len() < self.config.max_objects {
            self.data.insert(key.0, value);
        }
    }
}

impl Default for HotObjectCache {
    fn default() -> Self { Self::new(CacheConfig::default()) }
}

pub struct StateRootCache(std::collections::HashMap<u64, StateRoot>);
impl StateRootCache {
    pub fn new() -> Self { Self(std::collections::HashMap::new()) }
    pub fn put(&mut self, height: u64, root: StateRoot) { self.0.insert(height, root); }
    pub fn get(&self, height: u64) -> Option<StateRoot> { self.0.get(&height).copied() }
}
impl Default for StateRootCache { fn default() -> Self { Self::new() } }

pub struct StorageCache {
    pub objects: HotObjectCache,
    pub roots: StateRootCache,
    pub metrics: CacheMetrics,
}

impl StorageCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            objects: HotObjectCache::new(config),
            roots: StateRootCache::new(),
            metrics: CacheMetrics::default(),
        }
    }
}

/// Convenience: look up a cached object by its `ObjectId` directly.
pub struct ObjectIdCache {
    inner: HotObjectCache,
}

impl ObjectIdCache {
    /// Create an object-ID-keyed cache layer.
    pub fn new(config: CacheConfig) -> Self { Self { inner: HotObjectCache::new(config) } }

    /// Retrieve a cached object by `ObjectId`.
    pub fn get(&self, id: &ObjectId) -> Option<&StorageValue> {
        let key = StorageKey(id.as_hash().0.to_vec());
        self.inner.get(&key)
    }

    /// Insert an object into the cache.
    pub fn put(&mut self, id: &ObjectId, value: StorageValue) {
        let key = StorageKey(id.as_hash().0.to_vec());
        self.inner.put(key, value);
    }

    /// Returns `true` if the given object is cached.
    pub fn contains(&self, id: &ObjectId) -> bool {
        self.get(id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::primitives::{ObjectId, Hash256};
    use aevor_core::storage::{StorageKey, StorageValue};

    fn obj_id(n: u8) -> ObjectId { ObjectId(Hash256([n; 32])) }
    fn val(n: u8) -> StorageValue { StorageValue::from_bytes(vec![n]) }
    fn key(n: u8) -> StorageKey { StorageKey::from_bytes(vec![n]) }

    #[test]
    fn hot_cache_get_returns_none_before_put() {
        let cache = HotObjectCache::default();
        assert!(cache.get(&key(1)).is_none());
    }

    #[test]
    fn hot_cache_put_and_get() {
        let mut cache = HotObjectCache::new(CacheConfig::default());
        cache.put(key(1), val(42));
        assert_eq!(cache.get(&key(1)).unwrap().0, vec![42]);
    }

    #[test]
    fn hot_cache_respects_max_objects() {
        let config = CacheConfig { max_objects: 1, ..Default::default() };
        let mut cache = HotObjectCache::new(config);
        cache.put(key(1), val(1));
        // Second put should be silently ignored (at capacity)
        cache.put(key(2), val(2));
        assert!(cache.get(&key(1)).is_some());
        assert!(cache.get(&key(2)).is_none());
    }

    #[test]
    fn state_root_cache_put_and_get() {
        let mut cache = StateRootCache::new();
        let root = aevor_core::storage::StateRoot::EMPTY;
        cache.put(100, root);
        assert!(cache.get(100).is_some());
        assert!(cache.get(200).is_none());
    }

    #[test]
    fn cache_metrics_hit_rate_zero_when_empty() {
        let m = CacheMetrics::default();
        assert_eq!(m.hit_rate(), 0.0);
    }

    #[test]
    fn object_id_cache_put_contains_get() {
        let mut cache = ObjectIdCache::new(CacheConfig::default());
        let id = obj_id(5);
        assert!(!cache.contains(&id));
        cache.put(&id, val(99));
        assert!(cache.contains(&id));
        assert_eq!(cache.get(&id).unwrap().0, vec![99]);
    }
}
