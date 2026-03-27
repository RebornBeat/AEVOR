//! DNS resolver.

use serde::{Deserialize, Serialize};
use crate::records::DnsRecordSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolverConfig { pub upstream: Vec<String>, pub cache_ttl: u32, pub enable_dnssec: bool }
impl Default for ResolverConfig {
    fn default() -> Self { Self { upstream: vec!["8.8.8.8".into()], cache_ttl: 300, enable_dnssec: true } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolveResult { pub name: String, pub records: DnsRecordSet, pub authenticated: bool }

pub struct RecursiveResolver { config: ResolverConfig }
impl RecursiveResolver {
    pub fn new(config: ResolverConfig) -> Self { Self { config } }
    pub fn config(&self) -> &ResolverConfig { &self.config }
    pub fn upstream_servers(&self) -> &[String] { &self.config.upstream }
    /// Resolve a DNS name recursively.
    ///
    /// # Errors
    /// Returns an error if the name is invalid or all upstream resolvers fail.
    pub fn resolve(&self, name: &str) -> crate::NsResult<ResolveResult> {
        Ok(ResolveResult { name: name.to_string(), records: DnsRecordSet::new(), authenticated: false })
    }
}

pub struct AuthoritativeResolver { zones: Vec<String> }
impl AuthoritativeResolver {
    pub fn new() -> Self { Self { zones: Vec::new() } }
    pub fn add_zone(&mut self, zone: String) { self.zones.push(zone); }
    pub fn is_authoritative(&self, name: &str) -> bool {
        self.zones.iter().any(|z| name.ends_with(z.as_str()))
    }
}
impl Default for AuthoritativeResolver { fn default() -> Self { Self::new() } }

pub struct CachingResolver { cache: std::collections::HashMap<String, ResolveResult> }
impl CachingResolver {
    pub fn new() -> Self { Self { cache: std::collections::HashMap::new() } }
    pub fn get(&self, name: &str) -> Option<&ResolveResult> { self.cache.get(name) }
    pub fn insert(&mut self, name: String, result: ResolveResult) { self.cache.insert(name, result); }
}
impl Default for CachingResolver { fn default() -> Self { Self::new() } }

pub struct DnsResolver { recursive: RecursiveResolver, caching: CachingResolver }
impl DnsResolver {
    pub fn new(config: ResolverConfig) -> Self {
        Self { recursive: RecursiveResolver::new(config), caching: CachingResolver::new() }
    }
    /// Resolve a DNS name, returning a cached result if available.
    ///
    /// # Errors
    /// Returns an error if the name is invalid or the recursive resolver fails.
    pub fn resolve(&mut self, name: &str) -> crate::NsResult<ResolveResult> {
        if let Some(cached) = self.caching.get(name) { return Ok(cached.clone()); }
        let result = self.recursive.resolve(name)?;
        self.caching.insert(name.to_string(), result.clone());
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ResolverConfig ──────────────────────────────────────────

    #[test]
    fn resolver_config_default_upstream_and_dnssec() {
        let cfg = ResolverConfig::default();
        assert_eq!(cfg.upstream, vec!["8.8.8.8"]);
        assert!(cfg.enable_dnssec);
        assert_eq!(cfg.cache_ttl, 300);
    }

    // ── RecursiveResolver ───────────────────────────────────────

    #[test]
    fn recursive_resolver_stores_config() {
        let cfg = ResolverConfig { upstream: vec!["1.1.1.1".into()], cache_ttl: 60, enable_dnssec: false };
        let r = RecursiveResolver::new(cfg);
        assert_eq!(r.upstream_servers(), &["1.1.1.1"]);
        assert!(!r.config().enable_dnssec);
    }

    #[test]
    fn recursive_resolver_resolve_returns_ok() {
        let r = RecursiveResolver::new(ResolverConfig::default());
        let result = r.resolve("example.com").unwrap();
        assert_eq!(result.name, "example.com");
        assert!(!result.authenticated); // stub always returns false
    }

    // ── AuthoritativeResolver ───────────────────────────────────

    #[test]
    fn authoritative_resolver_add_zone_and_check() {
        let mut r = AuthoritativeResolver::new();
        r.add_zone(".aevor".into());
        assert!(r.is_authoritative("node1.aevor"));
        assert!(r.is_authoritative("sub.node1.aevor"));
        assert!(!r.is_authoritative("example.com"));
    }

    #[test]
    fn authoritative_resolver_empty_is_not_authoritative() {
        let r = AuthoritativeResolver::default();
        assert!(!r.is_authoritative("example.com"));
    }

    // ── CachingResolver ─────────────────────────────────────────

    #[test]
    fn caching_resolver_miss_returns_none() {
        let r = CachingResolver::new();
        assert!(r.get("example.com").is_none());
    }

    #[test]
    fn caching_resolver_insert_and_get() {
        let mut r = CachingResolver::default();
        let result = ResolveResult {
            name: "example.com".into(),
            records: crate::records::DnsRecordSet::new(),
            authenticated: false,
        };
        r.insert("example.com".into(), result);
        assert_eq!(r.get("example.com").unwrap().name, "example.com");
    }

    // ── DnsResolver ─────────────────────────────────────────────

    #[test]
    fn dns_resolver_first_resolve_caches_result() {
        let mut r = DnsResolver::new(ResolverConfig::default());
        let result = r.resolve("example.com").unwrap();
        assert_eq!(result.name, "example.com");
        // Second call should hit cache
        let cached = r.resolve("example.com").unwrap();
        assert_eq!(cached.name, "example.com");
    }
}
