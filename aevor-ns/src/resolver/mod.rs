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
    pub fn resolve(&mut self, name: &str) -> crate::NsResult<ResolveResult> {
        if let Some(cached) = self.caching.get(name) { return Ok(cached.clone()); }
        let result = self.recursive.resolve(name)?;
        self.caching.insert(name.to_string(), result.clone());
        Ok(result)
    }
}
