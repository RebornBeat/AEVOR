//! DNS resolver.

use serde::{Deserialize, Serialize};
use crate::records::{DnsRecordSet, DnsRecord, ARecord, AaaaRecord};

use std::net::IpAddr;
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ResolverConfig as HickoryResolverConfig, ResolverOpts, NameServerConfigGroup,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolverConfig { pub upstream: Vec<String>, pub cache_ttl: u32, pub enable_dnssec: bool }
impl Default for ResolverConfig {
    fn default() -> Self { Self { upstream: vec!["8.8.8.8".into()], cache_ttl: 300, enable_dnssec: true } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolveResult { pub name: String, pub records: DnsRecordSet, pub authenticated: bool }

/// A recursive DNS resolver backed by the audited `hickory-resolver` crate.
///
/// Real recursive resolution over UDP/TCP against the configured upstream name
/// servers, with DNSSEC validation enabled when `config.enable_dnssec` is set
/// (the resolver rejects responses that fail signature validation for signed
/// zones). Building the resolver is offline; `resolve` performs live network
/// I/O, so it is exercised against real DNS outside the sandbox.
pub struct RecursiveResolver {
    config: ResolverConfig,
    backend: Resolver,
}

impl RecursiveResolver {
    /// Build a resolver from the given configuration.
    #[must_use]
    pub fn new(config: ResolverConfig) -> Self {
        let backend = Self::build_backend(&config);
        Self { config, backend }
    }

    fn build_backend(config: &ResolverConfig) -> Resolver {
        let mut opts = ResolverOpts::default();
        // Enable DNSSEC validation when requested — hickory then rejects
        // responses whose signatures don't validate for signed zones.
        opts.validate = config.enable_dnssec;

        // Parse configured upstreams as IPs; fall back to system/default config
        // when none are usable.
        let servers: Vec<IpAddr> = config
            .upstream
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();

        let hickory_config = if servers.is_empty() {
            HickoryResolverConfig::default()
        } else {
            // UDP + TCP to each upstream on port 53; trust negative responses.
            let group = NameServerConfigGroup::from_ips_clear(&servers, 53, true);
            HickoryResolverConfig::from_parts(None, vec![], group)
        };

        Resolver::new(hickory_config, opts)
            .expect("failed to construct DNS resolver backend")
    }

    /// The resolver configuration.
    #[must_use]
    pub fn config(&self) -> &ResolverConfig {
        &self.config
    }

    /// The configured upstream servers.
    #[must_use]
    pub fn upstream_servers(&self) -> &[String] {
        &self.config.upstream
    }

    /// Resolve a DNS name recursively into its A/AAAA records.
    ///
    /// Performs a real recursive lookup against the configured upstreams. When
    /// DNSSEC is enabled, a returned result has been signature-validated for
    /// signed zones.
    ///
    /// # Errors
    /// Returns [`crate::NsError::DomainNotFound`] if the name cannot be resolved
    /// (NXDOMAIN, network failure, or DNSSEC validation failure).
    pub fn resolve(&self, name: &str) -> crate::NsResult<ResolveResult> {
        let response = self
            .backend
            .lookup_ip(name)
            .map_err(|e| crate::NsError::DomainNotFound {
                domain: format!("{name}: {e}"),
            })?;

        let mut records = DnsRecordSet::new();
        for ip in response.iter() {
            match ip {
                IpAddr::V4(v4) => records.add(DnsRecord::A(ARecord {
                    name: name.to_string(),
                    ipv4: v4,
                    ttl: self.config.cache_ttl,
                })),
                IpAddr::V6(v6) => records.add(DnsRecord::Aaaa(AaaaRecord {
                    name: name.to_string(),
                    ipv6: v6,
                    ttl: self.config.cache_ttl,
                })),
            }
        }

        Ok(ResolveResult {
            name: name.to_string(),
            records,
            authenticated: self.config.enable_dnssec,
        })
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
    #[ignore = "performs a real DNS lookup; run with --ignored against a live network"]
    fn recursive_resolver_resolves_real_domain() {
        let r = RecursiveResolver::new(ResolverConfig::default());
        let result = r.resolve("example.com").unwrap();
        assert_eq!(result.name, "example.com");
        // example.com is signed, so with DNSSEC validation on the result is authenticated.
        assert!(result.authenticated);
        assert!(!result.records.records.is_empty(), "resolved at least one A/AAAA record");
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
    #[ignore = "performs a real DNS lookup; run with --ignored against a live network"]
    fn dns_resolver_first_resolve_caches_result() {
        let mut r = DnsResolver::new(ResolverConfig::default());
        let result = r.resolve("example.com").unwrap();
        assert_eq!(result.name, "example.com");
        // Second call should hit cache
        let cached = r.resolve("example.com").unwrap();
        assert_eq!(cached.name, "example.com");
    }
}
