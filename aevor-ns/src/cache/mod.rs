//! DNS response caching with TTL-based expiration.

use serde::{Deserialize, Serialize};
use crate::records::DnsRecordSet;

/// Statistics for the DNS response cache.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DnsCache {
    /// Number of cache hits (responses served from cache).
    pub hits: u64,
    /// Number of cache misses (required upstream resolution).
    pub misses: u64,
    /// Current number of cached entries.
    pub entries: usize,
}

impl DnsCache {
    /// Hit rate as a percentage (0–100).
    #[allow(clippy::cast_precision_loss)] // hit/miss counts: precision loss acceptable for metrics
    pub fn hit_rate_pct(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 * 100.0 }
    }
}

/// A cached DNS response entry.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// The cached record set.
    pub records: DnsRecordSet,
    /// Time-to-live in seconds remaining.
    pub ttl_remaining: u32,
    /// When this entry was cached (monotonic seconds).
    pub cached_at: u64,
}

impl CacheEntry {
    /// Create a new cache entry.
    pub fn new(records: DnsRecordSet, ttl: u32, now: u64) -> Self {
        Self { records, ttl_remaining: ttl, cached_at: now }
    }

    /// Returns `true` if this entry has expired.
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.cached_at) >= u64::from(self.ttl_remaining)
    }
}

/// In-memory DNS response cache with TTL eviction.
pub struct ResponseCache {
    entries: std::collections::HashMap<String, CacheEntry>,
    stats: DnsCache,
}

impl ResponseCache {
    /// Create a new empty response cache.
    pub fn new() -> Self {
        Self { entries: std::collections::HashMap::new(), stats: DnsCache::default() }
    }

    /// Look up a cached response by name.
    pub fn get(&mut self, name: &str, now: u64) -> Option<&DnsRecordSet> {
        if let Some(entry) = self.entries.get(name) {
            if entry.is_expired(now) {
                self.entries.remove(name);
                self.stats.entries = self.entries.len();
                self.stats.misses += 1;
                return None;
            }
            self.stats.hits += 1;
            return self.entries.get(name).map(|e| &e.records);
        }
        self.stats.misses += 1;
        None
    }

    /// Insert a response into the cache with the given TTL.
    pub fn insert(&mut self, name: String, records: DnsRecordSet, ttl: u32, now: u64) {
        self.entries.insert(name, CacheEntry::new(records, ttl, now));
        self.stats.entries = self.entries.len();
    }

    /// Current cache statistics.
    pub fn stats(&self) -> &DnsCache { &self.stats }

    /// Remove all expired entries.
    pub fn evict_expired(&mut self, now: u64) {
        self.entries.retain(|_, e| !e.is_expired(now));
        self.stats.entries = self.entries.len();
    }
}

impl Default for ResponseCache {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::DnsRecordSet;

    fn records() -> DnsRecordSet { DnsRecordSet::new() }

    #[test]
    fn dns_cache_hit_rate_zero_when_empty() {
        let c = DnsCache::default();
        assert_eq!(c.hit_rate_pct(), 0.0);
    }

    #[test]
    fn dns_cache_hit_rate_all_hits() {
        let c = DnsCache { hits: 10, misses: 0, entries: 0 };
        assert!((c.hit_rate_pct() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn dns_cache_hit_rate_half() {
        let c = DnsCache { hits: 5, misses: 5, entries: 0 };
        assert!((c.hit_rate_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn cache_entry_not_expired_during_ttl() {
        let entry = CacheEntry::new(records(), 3600, 1000);
        assert!(!entry.is_expired(2000)); // only 1000s elapsed
    }

    #[test]
    fn cache_entry_expired_after_ttl() {
        let entry = CacheEntry::new(records(), 3600, 1000);
        assert!(entry.is_expired(4600)); // 3600s elapsed
    }

    #[test]
    fn response_cache_insert_and_get() {
        let mut cache = ResponseCache::new();
        cache.insert("example.com".into(), records(), 3600, 1000);
        // Within TTL
        let result = cache.get("example.com", 2000);
        assert!(result.is_some());
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn response_cache_get_missing_returns_none_and_increments_misses() {
        let mut cache = ResponseCache::new();
        let result = cache.get("unknown.com", 1000);
        assert!(result.is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn response_cache_get_expired_returns_none() {
        let mut cache = ResponseCache::new();
        cache.insert("example.com".into(), records(), 60, 1000);
        // Now at 5000 — 4000s > 60s TTL
        let result = cache.get("example.com", 5000);
        assert!(result.is_none());
        assert_eq!(cache.stats().entries, 0);
    }

    #[test]
    fn response_cache_evict_expired_removes_stale_entries() {
        let mut cache = ResponseCache::new();
        cache.insert("fresh.com".into(), records(), 3600, 1000);
        cache.insert("stale.com".into(), records(), 10, 1000);
        // At t=2000: stale.com TTL=10s is expired, fresh.com is not
        cache.evict_expired(2000);
        assert_eq!(cache.stats().entries, 1);
        assert!(cache.get("fresh.com", 2000).is_some());
    }
}
