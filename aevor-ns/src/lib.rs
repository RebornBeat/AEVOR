//! # AEVOR NS: Privacy-Aware Domain Resolution
//!
//! `aevor-ns` provides AEVOR's naming infrastructure, combining standard DNS protocol
//! compatibility for internet integration with privacy-preserving service discovery
//! and multi-network domain management.
//!
//! ## Architectural Boundary
//!
//! This crate provides DNS infrastructure capabilities:
//! - Standard DNS record management and resolution (A, AAAA, MX, TXT, CNAME, NS, PTR, SRV)
//! - DNSSEC security for cryptographic verification of DNS responses
//! - TEE service discovery integration through DNS-compatible mechanisms
//! - Privacy-preserving resolution that doesn't create surveillance capabilities
//! - Multi-network domain coordination across permissionless and permissioned deployments
//!
//! Application-specific DNS coordination (email routing logic, CDN routing policies,
//! service mesh protocols) belongs in applications that use these infrastructure primitives.
//!
//! ## DNS Infrastructure vs Service Coordination
//!
//! ```text
//! aevor-ns provides:           Applications implement:
//! ─────────────────────        ─────────────────────────
//! MX record resolution    →    Email routing logic
//! SRV record management   →    Service mesh policies
//! A/AAAA resolution       →    Load balancing decisions
//! TXT record storage      →    SPF/DKIM/DMARC validation
//! Privacy-preserving      →    Anti-surveillance products
//! TEE service discovery   →    Service allocation strategy
//! ```
//!
//! ## Internet Compatibility
//!
//! All standard DNS operations are fully compatible with existing DNS resolvers,
//! web browsers, email clients, and internet infrastructure without modification.
//! AEVOR-specific extensions are additive and optional.
//!
//! ## Privacy-Preserving Resolution
//!
//! DNS queries can be submitted through TEE-encrypted channels that prevent
//! infrastructure providers from building browsing profiles or service usage patterns.

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// DNS resolver: recursive and authoritative resolution with caching.
pub mod resolver;

/// Domain registry: registration, transfer, and lifecycle management.
pub mod registry;

/// DNS records: all standard record types plus AEVOR extensions.
pub mod records;

/// Privacy-preserving resolution: confidential DNS queries through TEE channels.
pub mod privacy;

/// TEE service discovery: integration between DNS and TEE service allocation.
pub mod tee_discovery;

/// DNSSEC: cryptographic signing and verification of DNS records.
pub mod dnssec;

/// Multi-network domain management: coordinating domains across network types.
pub mod multi_network;

/// DNS caching: intelligent caching with TTL management and invalidation.
pub mod cache;

/// Zone management: authoritative zone data and delegation.
pub mod zones;

/// Protocol implementation: DNS wire format, query/response handling.
pub mod protocol;

// ============================================================
// PRELUDE
// ============================================================

/// NS prelude — all essential naming infrastructure types.
///
/// ```rust
/// use aevor_ns::prelude::*;
/// ```
pub mod prelude {
    pub use crate::resolver::{
        DnsResolver, ResolverConfig, ResolveResult, RecursiveResolver,
        AuthoritativeResolver, CachingResolver,
    };
    pub use crate::registry::{
        DomainRegistry, DomainRecord, RegistrationRequest, RegistrationResult,
        DomainTransfer, DomainRenewal, DomainOwnership,
    };
    pub use crate::records::{
        DnsRecord, RecordType, ARecord, AaaaRecord, MxRecord, TxtRecord,
        CnameRecord, NsRecord, PtrRecord, SrvRecord, DnsRecordSet,
    };
    pub use crate::privacy::{
        PrivateResolver, ConfidentialQuery, ResolutionPrivacy,
        AntiSurveillanceDns, TeeEncryptedResolution,
    };
    pub use crate::tee_discovery::{
        TeeServiceRecord, ServiceDiscoveryDns, TeeEndpointRecord,
        ServiceCapabilityRecord, DiscoveryQuery,
    };
    pub use crate::dnssec::{
        DnssecSigner, DnssecVerifier, DnsKey, Rrsig, Nsec, Ds,
        DnssecChain, DnssecValidation,
    };
    pub use crate::multi_network::{
        MultiNetworkDomain, NetworkDomainPolicy, CrossNetworkResolution,
        SubnetDomain, HybridDomainConfig,
    };
    pub use crate::zones::{
        Zone, ZoneData, ZoneTransfer, AuthoritativeZone,
        ZoneDelegate, SoaRecord,
    };
    pub use crate::{NsError, NsResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from naming infrastructure operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum NsError {
    /// Domain name does not exist (NXDOMAIN).
    #[error("domain not found: {domain}")]
    DomainNotFound {
        /// Domain that was queried.
        domain: String,
    },

    /// Record type not found for an existing domain (NOERROR/NODATA).
    #[error("record type {record_type} not found for domain {domain}")]
    RecordNotFound {
        /// Domain that was queried.
        domain: String,
        /// Record type that was requested.
        record_type: String,
    },

    /// DNSSEC validation failed.
    #[error("DNSSEC validation failed for {domain}: {reason}")]
    DnssecValidationFailed {
        /// Domain whose DNSSEC validation failed.
        domain: String,
        /// Reason for validation failure.
        reason: String,
    },

    /// Domain registration failed.
    #[error("domain registration failed for {domain}: {reason}")]
    RegistrationFailed {
        /// Domain that could not be registered.
        domain: String,
        /// Reason for failure.
        reason: String,
    },

    /// Domain is already registered by another party.
    #[error("domain already registered: {domain}")]
    DomainAlreadyRegistered {
        /// Domain that is already taken.
        domain: String,
    },

    /// Zone transfer failed.
    #[error("zone transfer failed for {zone}: {reason}")]
    ZoneTransferFailed {
        /// Zone name.
        zone: String,
        /// Reason for failure.
        reason: String,
    },

    /// Invalid domain name format.
    #[error("invalid domain name: {name}")]
    InvalidDomainName {
        /// Invalid domain name.
        name: String,
    },
}

/// Convenience alias for naming infrastructure results.
pub type NsResult<T> = Result<T, NsError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Maximum domain name length in characters (RFC 1035).
pub const MAX_DOMAIN_NAME_LENGTH: usize = 253;

/// Maximum DNS label length in characters (RFC 1035).
pub const MAX_LABEL_LENGTH: usize = 63;

/// Maximum TTL in seconds (68 years per RFC 2181).
pub const MAX_TTL_SECONDS: u32 = 2_147_483_647;

/// Default TTL for AEVOR domain records in seconds.
pub const DEFAULT_TTL_SECONDS: u32 = 300;

/// Maximum TXT record content length in bytes.
pub const MAX_TXT_RECORD_BYTES: usize = 65_535;

/// Default DNS cache capacity in record count.
pub const DEFAULT_CACHE_CAPACITY: usize = 100_000;

/// AEVOR DNS extension record type ID (private use range).
pub const AEVOR_TEE_RECORD_TYPE: u16 = 65_400;

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_constants_match_rfc() {
        assert_eq!(MAX_DOMAIN_NAME_LENGTH, 253);
        assert_eq!(MAX_LABEL_LENGTH, 63);
    }

    #[test]
    fn aevor_record_type_is_in_private_range() {
        // IANA private use range: 65280–65534
        assert!(AEVOR_TEE_RECORD_TYPE >= 65_280);
        assert!(AEVOR_TEE_RECORD_TYPE <= 65_534);
    }


    #[test]
    fn ns_error_display() {
        let e = NsError::DomainNotFound { domain: "example.aevor".into() };
        assert!(e.to_string().contains("example.aevor"));
    }

    #[test]
    fn dns_message_query_is_not_response() {
        use crate::protocol::DnsMessage;
        let msg = DnsMessage::query(1, vec!["example.aevor".into()]);
        assert!(!msg.is_response);
        assert_eq!(msg.id, 1);
    }

    #[test]
    fn dns_message_nxdomain_is_response() {
        use crate::protocol::DnsMessage;
        let query = DnsMessage::query(42, vec!["notfound.aevor".into()]);
        let nx = DnsMessage::nxdomain(&query);
        assert!(nx.is_response);
        assert_eq!(nx.id, 42);
        assert!(!nx.is_success());
    }

    #[test]
    fn cache_starts_empty() {
        use crate::cache::ResponseCache;
        let cache = ResponseCache::new();
        assert_eq!(cache.stats().hits, 0);
        assert_eq!(cache.stats().entries, 0);
    }

    #[test]
    fn cache_hit_rate_zero_when_empty() {
        use crate::cache::{DnsCache};
        let stats = DnsCache::default();
        assert_eq!(stats.hit_rate_pct(), 0.0);
    }

    #[test]
    fn cache_hit_rate_calculation() {
        use crate::cache::DnsCache;
        let stats = DnsCache { hits: 3, misses: 1, entries: 4 };
        assert_eq!(stats.hit_rate_pct(), 75.0);
    }
}
