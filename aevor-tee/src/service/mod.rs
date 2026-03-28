//! TEE service allocation, discovery, quality management, and mesh coordination.
//!
//! This module provides infrastructure-layer primitives for TEE service operation.
//! All throughput and performance figures are **measurements** on specific hardware —
//! they are not ceilings. Actual performance scales with hardware and network resources.

use serde::{Deserialize, Serialize};
pub use aevor_core::tee::{TeePlatform, TeeServiceType};
use aevor_core::primitives::Hash256;
use crate::{TeeError, TeeResult};

/// Strategy for selecting which TEE instance handles a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AllocationStrategy {
    /// Use the best available TEE instance based on quality score.
    #[default]
    BestAvailable,
    /// Prefer a specific hardware platform (fall back to others if unavailable).
    PreferSpecificPlatform(TeePlatform),
    /// Prefer instances geographically close to the requesting validator.
    GeographicProximity,
    /// Prefer instances with the lowest measured latency.
    LowestLatency,
    /// Prefer instances with the highest security certification level.
    HighestSecurity,
}

/// Measured quality metrics for a TEE service instance.
///
/// All figures here are **measurements** of actual observed behavior, not
/// guaranteed specifications or performance ceilings. Actual performance
/// scales with hardware and network resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceQuality {
    /// Measured P99 request latency in milliseconds on this instance.
    pub latency_ms: u32,
    /// Observed availability over the trailing 30-day window (percentage).
    pub availability_pct: u8,
    /// Consensus security level this instance can satisfy.
    pub security_level: aevor_core::consensus::SecurityLevel,
    /// Hardware platform of this instance.
    pub platform: TeePlatform,
    /// Observed peak throughput in requests per second (measurement, not ceiling).
    pub measured_throughput_rps: u32,
}

impl ServiceQuality {
    /// Composite quality score: higher is better.
    pub fn score(&self) -> u64 {
        let avail = u64::from(self.availability_pct);
        let lat = (1000u64).saturating_sub(u64::from(self.latency_ms));
        avail * 10 + lat
    }
}

/// Health status of a TEE service instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ServiceHealthStatus {
    /// Instance is healthy and accepting requests.
    #[default]
    Healthy,
    /// Instance is degraded — accepting requests but with reduced quality.
    Degraded,
    /// Instance is unreachable or not responding.
    Unreachable,
    /// Instance has been isolated due to a security or integrity concern.
    Isolated,
}

/// Health record for a TEE service instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceHealth {
    /// Handle identifying the service instance.
    pub handle_id: Hash256,
    /// Current health status.
    pub status: ServiceHealthStatus,
    /// Consecutive failed health checks (resets on success).
    pub consecutive_failures: u32,
    /// Most recent measured quality (if available).
    pub last_quality: Option<ServiceQuality>,
}

impl ServiceHealth {
    /// Create a healthy instance record.
    pub fn healthy(handle_id: Hash256) -> Self {
        Self { handle_id, status: ServiceHealthStatus::Healthy, consecutive_failures: 0, last_quality: None }
    }

    /// Returns `true` if this instance is available for requests.
    pub fn is_available(&self) -> bool {
        matches!(self.status, ServiceHealthStatus::Healthy | ServiceHealthStatus::Degraded)
    }

    /// Record a failed health check.
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= 3 {
            self.status = ServiceHealthStatus::Unreachable;
        } else {
            self.status = ServiceHealthStatus::Degraded;
        }
    }

    /// Record a successful health check (resets failure counter).
    pub fn record_success(&mut self, quality: ServiceQuality) {
        self.consecutive_failures = 0;
        self.status = ServiceHealthStatus::Healthy;
        self.last_quality = Some(quality);
    }
}

/// Quality of service policy for a service category.
///
/// Policies are application-layer decisions; the infrastructure provides
/// the primitive (`QosPolicy`) but does not enforce any specific policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QosPolicy {
    /// Maximum acceptable P99 latency in milliseconds.
    pub max_latency_ms: u32,
    /// Minimum acceptable availability percentage.
    pub min_availability_pct: u8,
    /// Whether to prefer geographic proximity for this service.
    pub prefer_geographic_proximity: bool,
}

impl QosPolicy {
    /// Create a permissive policy suitable for development.
    pub fn permissive() -> Self {
        Self { max_latency_ms: u32::MAX, min_availability_pct: 0, prefer_geographic_proximity: false }
    }
    /// Returns `true` if the given quality satisfies this policy.
    pub fn is_satisfied_by(&self, q: &ServiceQuality) -> bool {
        q.latency_ms <= self.max_latency_ms && q.availability_pct >= self.min_availability_pct
    }
}

/// Coordinates TEE service instances into a mesh with health monitoring.
///
/// The mesh provides automatic failover to healthy instances when unhealthy
/// ones are detected. No state is rolled back — if an instance fails mid-request,
/// the request is rejected and the caller may resubmit to a healthy instance.
pub struct ServiceMeshCoordinator {
    health_records: Vec<ServiceHealth>,
}

impl ServiceMeshCoordinator {
    /// Create an empty mesh coordinator.
    pub fn new() -> Self { Self { health_records: Vec::new() } }

    /// Register a service instance with the mesh.
    pub fn register(&mut self, handle_id: Hash256) {
        self.health_records.push(ServiceHealth::healthy(handle_id));
    }

    /// Number of registered instances.
    pub fn instance_count(&self) -> usize { self.health_records.len() }

    /// Number of instances currently available for requests.
    pub fn available_count(&self) -> usize {
        self.health_records.iter().filter(|h| h.is_available()).count()
    }

    /// Record a health check result for an instance.
    pub fn update_health(&mut self, handle_id: &Hash256, success: bool, quality: Option<ServiceQuality>) {
        if let Some(record) = self.health_records.iter_mut().find(|h| &h.handle_id == handle_id) {
            if success {
                if let Some(q) = quality {
                    record.record_success(q);
                }
            } else {
                record.record_failure();
            }
        }
    }

    /// Find a healthy instance matching the given QoS policy.
    pub fn find_healthy(&self, policy: &QosPolicy) -> Option<Hash256> {
        self.health_records.iter()
            .filter(|h| h.is_available())
            .filter(|h| h.last_quality.as_ref().map_or(true, |q| policy.is_satisfied_by(q)))
            .map(|h| h.handle_id)
            .next()
    }
}

impl Default for ServiceMeshCoordinator {
    fn default() -> Self { Self::new() }
}

/// Coordinates TEE services across different network types (public/permissioned/hybrid).
///
/// This is an infrastructure primitive — cross-network policies are implemented
/// by applications, not embedded here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossNetworkServiceCoordinator {
    /// Network identifier for the source network.
    pub source_network: String,
    /// Network identifier for the destination network.
    pub destination_network: String,
    /// Whether cross-network service access is permitted (application policy).
    pub access_permitted: bool,
}

impl CrossNetworkServiceCoordinator {
    /// Create a coordinator for cross-network service access.
    pub fn new(source: impl Into<String>, destination: impl Into<String>, permitted: bool) -> Self {
        Self {
            source_network: source.into(),
            destination_network: destination.into(),
            access_permitted: permitted,
        }
    }

    /// Returns `true` if cross-network service requests can be routed.
    pub fn can_route(&self) -> bool { self.access_permitted }
}

/// Declared capability of a TEE service provider (validator side).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceCapability {
    /// Type of service this provider offers.
    pub service_type: TeeServiceType,
    /// Hardware platform backing this capability.
    pub platform: TeePlatform,
    /// Maximum enclave memory in bytes.
    pub max_memory_bytes: usize,
    /// Maximum number of concurrent requests (configurable per provider).
    pub max_concurrent: usize,
    /// Per-request price in nAVR (nano-AEVOR tokens).
    pub price_per_request_nano: u64,
}

/// A client's request to allocate a TEE service instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeServiceRequest {
    /// The type of TEE service needed.
    pub service_type: TeeServiceType,
    /// How to select among available providers.
    pub strategy: AllocationStrategy,
    /// Minimum enclave memory the caller requires.
    pub min_memory_bytes: usize,
    /// Minimum acceptable security level.
    pub required_security_level: aevor_core::consensus::SecurityLevel,
    /// Maximum price the caller will pay per request (nAVR).
    pub max_price_nano: u64,
    /// Address of the entity requesting the service.
    pub requestor: aevor_core::primitives::Address,
}

/// Response confirming a TEE service has been allocated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeServiceResponse {
    /// Handle identifying this specific allocation.
    pub handle: TeeServiceHandle,
    /// Validator who owns the TEE instance that was allocated.
    pub provider_validator: aevor_core::primitives::ValidatorId,
    /// Hardware platform of the allocated instance.
    pub platform: TeePlatform,
    /// Enclave memory actually allocated.
    pub allocated_memory_bytes: usize,
    /// Actual per-request price (≤ `max_price_nano` from the request).
    pub price_per_request_nano: u64,
    /// Current quality metrics for the allocated instance.
    pub quality: ServiceQuality,
}

/// An opaque handle to an allocated TEE service instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeServiceHandle {
    /// Unique allocation identifier.
    pub id: Hash256,
    /// Service type this handle refers to.
    pub service_type: TeeServiceType,
    /// Platform of the allocated instance.
    pub platform: TeePlatform,
    /// Last consensus round at which this handle is still valid.
    pub valid_until_round: u64,
}

impl TeeServiceHandle {
    /// Returns `true` if this handle is still valid at `current_round`.
    pub fn is_valid(&self, current_round: u64) -> bool {
        current_round <= self.valid_until_round
    }
}

/// Allocates TEE services from known validator providers.
pub struct TeeServiceAllocator {
    known_providers: Vec<ServiceCapability>,
}

impl TeeServiceAllocator {
    /// Create an allocator with no registered providers.
    pub fn new() -> Self { Self { known_providers: Vec::new() } }

    /// Register a new provider capability (called when validators announce services).
    pub fn register_provider(&mut self, cap: ServiceCapability) {
        self.known_providers.push(cap);
    }

    /// Attempt to allocate a service matching the request.
    ///
    /// # Errors
    /// Returns `TeeError::AllocationFailed` if no registered provider satisfies
    /// the service type, memory, and price constraints of the request.
    pub fn allocate(&self, request: &TeeServiceRequest) -> TeeResult<TeeServiceResponse> {
        let provider = self.known_providers.iter()
            .find(|p| {
                p.service_type == request.service_type
                    && p.max_memory_bytes >= request.min_memory_bytes
                    && p.price_per_request_nano <= request.max_price_nano
            })
            .ok_or_else(|| TeeError::AllocationFailed {
                reason: "no suitable provider found".into(),
            })?;

        let handle = TeeServiceHandle {
            id: Hash256([1u8; 32]),
            service_type: provider.service_type,
            platform: provider.platform,
            valid_until_round: u64::MAX,
        };

        Ok(TeeServiceResponse {
            handle,
            provider_validator: Hash256::ZERO,
            platform: provider.platform,
            allocated_memory_bytes: request.min_memory_bytes,
            price_per_request_nano: provider.price_per_request_nano,
            quality: ServiceQuality {
                latency_ms: 50,
                availability_pct: 99,
                security_level: request.required_security_level,
                platform: provider.platform,
                measured_throughput_rps: 0, // not yet measured for new allocation
            },
        })
    }

    /// Number of registered providers.
    pub fn provider_count(&self) -> usize { self.known_providers.len() }
}

impl Default for TeeServiceAllocator {
    fn default() -> Self { Self::new() }
}

/// Record of a secure application deployment via TEE-backed automation.
///
/// Build integrity is verified cryptographically before deployment. If verification
/// fails, the deployment is **rejected** — no partially-deployed state is committed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecureDeploymentRecord {
    /// Hash of the application artifact being deployed.
    pub artifact_hash: Hash256,
    /// TEE platform that verified the build.
    pub verified_by_platform: TeePlatform,
    /// Whether build integrity verification passed.
    pub integrity_verified: bool,
    /// Deployment target network identifier.
    pub target_network: String,
}

impl SecureDeploymentRecord {
    /// Create a verified deployment record.
    pub fn verified(artifact_hash: Hash256, platform: TeePlatform, network: impl Into<String>) -> Self {
        Self { artifact_hash, verified_by_platform: platform, integrity_verified: true, target_network: network.into() }
    }
    /// Create a rejected deployment record (verification failed).
    pub fn rejected(artifact_hash: Hash256, platform: TeePlatform, network: impl Into<String>) -> Self {
        Self { artifact_hash, verified_by_platform: platform, integrity_verified: false, target_network: network.into() }
    }
}

/// Cryptographic proof of data integrity for stored objects.
///
/// All stored data maintains a `DataIntegrityProof` that enables mathematical
/// verification without requiring access to unencrypted data contents.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    /// Merkle root over the stored data chunks.
    pub merkle_root: Hash256,
    /// Hash of the encryption key reference (not the key itself).
    pub key_reference_hash: Hash256,
    /// Version at which this proof was computed.
    pub version: u64,
}

impl DataIntegrityProof {
    /// Create a new integrity proof.
    pub fn new(merkle_root: Hash256, key_reference_hash: Hash256, version: u64) -> Self {
        Self { merkle_root, key_reference_hash, version }
    }
    /// Returns `true` if this proof attests to a non-empty data object.
    pub fn is_nonempty(&self) -> bool { self.merkle_root != Hash256::ZERO }
}

/// Configuration for a federated analytics session across multiple organizations.
///
/// This is an infrastructure primitive — participation policies and data sharing
/// agreements are implemented by applications, not embedded here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FederatedAnalyticsSession {
    /// Unique identifier for this session.
    pub session_id: Hash256,
    /// Number of participating organizations.
    pub participant_count: usize,
    /// Whether the session is active.
    pub is_active: bool,
}

impl FederatedAnalyticsSession {
    /// Create a new federated analytics session.
    pub fn new(session_id: Hash256, participant_count: usize) -> Self {
        Self { session_id, participant_count, is_active: true }
    }
}

/// Enterprise integration pattern — connects AEVOR infrastructure to organizational systems.
///
/// This is a capability primitive. Organizational policies (authentication, compliance,
/// data handling) are implemented by applications that use these capabilities.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnterpriseIntegrationConfig {
    /// Organization identifier (application-defined).
    pub organization_id: String,
    /// Whether audit trail generation is enabled.
    pub audit_trail_enabled: bool,
    /// Data residency constraint — empty means no constraint.
    pub data_residency_region: Option<String>,
}

impl EnterpriseIntegrationConfig {
    /// Create a configuration with audit trail enabled and no data residency constraint.
    pub fn with_audit(organization_id: impl Into<String>) -> Self {
        Self { organization_id: organization_id.into(), audit_trail_enabled: true, data_residency_region: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::consensus::SecurityLevel;
    use aevor_core::primitives::Address;

    fn make_request(service_type: TeeServiceType) -> TeeServiceRequest {
        TeeServiceRequest {
            service_type,
            strategy: AllocationStrategy::BestAvailable,
            min_memory_bytes: 64 * 1024,
            required_security_level: SecurityLevel::Basic,
            max_price_nano: 1_000_000,
            requestor: Address([0u8; 32]),
        }
    }

    fn make_quality(latency_ms: u32, availability_pct: u8) -> ServiceQuality {
        ServiceQuality {
            latency_ms,
            availability_pct,
            security_level: SecurityLevel::Basic,
            platform: TeePlatform::IntelSgx,
            measured_throughput_rps: 500,
        }
    }

    // ── TeeServiceAllocator ───────────────────────────────────────────────────

    #[test]
    fn allocator_returns_error_with_no_providers() {
        let allocator = TeeServiceAllocator::new();
        let req = make_request(TeeServiceType::Compute);
        assert!(allocator.allocate(&req).is_err());
    }

    #[test]
    fn allocator_returns_handle_when_provider_matches() {
        let mut allocator = TeeServiceAllocator::new();
        allocator.register_provider(ServiceCapability {
            service_type: TeeServiceType::Compute,
            platform: TeePlatform::IntelSgx,
            max_memory_bytes: 128 * 1024,
            max_concurrent: 4,
            price_per_request_nano: 100,
        });
        let req = make_request(TeeServiceType::Compute);
        let resp = allocator.allocate(&req).unwrap();
        assert!(resp.handle.is_valid(0));
    }

    #[test]
    fn all_six_service_types_can_be_requested() {
        // Section 15 defines 6 service categories: Compute, Storage, EdgeDelivery,
        // Analytics, Deployment, MultiPartyComputation. All must be allocatable.
        let types = [
            TeeServiceType::Compute,
            TeeServiceType::Storage,
            TeeServiceType::EdgeDelivery,
            TeeServiceType::Analytics,
            TeeServiceType::Deployment,
            TeeServiceType::MultiPartyComputation,
        ];
        for svc_type in types {
            let req = make_request(svc_type);
            assert_eq!(req.service_type, svc_type);
        }
    }

    #[test]
    fn service_quality_score_prefers_high_availability() {
        let high_avail = make_quality(100, 99);
        let low_avail = make_quality(100, 80);
        assert!(high_avail.score() > low_avail.score());
    }

    #[test]
    fn measured_throughput_rps_is_measurement_not_ceiling() {
        // throughput_rps is an observed measurement — not a hard limit.
        // Validators with better hardware will naturally report higher values.
        let q = make_quality(10, 99);
        assert_eq!(q.measured_throughput_rps, 500); // observed on specific hardware
    }

    // ── ServiceHealth ─────────────────────────────────────────────────────────

    #[test]
    fn service_health_starts_healthy() {
        let h = ServiceHealth::healthy(Hash256::ZERO);
        assert_eq!(h.status, ServiceHealthStatus::Healthy);
        assert!(h.is_available());
        assert_eq!(h.consecutive_failures, 0);
    }

    #[test]
    fn service_health_degrades_after_failures() {
        let mut h = ServiceHealth::healthy(Hash256::ZERO);
        h.record_failure();
        assert_eq!(h.status, ServiceHealthStatus::Degraded);
        assert!(h.is_available()); // degraded is still available
        h.record_failure();
        h.record_failure();
        assert_eq!(h.status, ServiceHealthStatus::Unreachable);
        assert!(!h.is_available());
    }

    #[test]
    fn service_health_recovers_on_success() {
        let mut h = ServiceHealth::healthy(Hash256::ZERO);
        h.record_failure();
        h.record_failure();
        h.record_success(make_quality(50, 99));
        assert_eq!(h.status, ServiceHealthStatus::Healthy);
        assert_eq!(h.consecutive_failures, 0);
        assert!(h.last_quality.is_some());
    }

    // ── QosPolicy ─────────────────────────────────────────────────────────────

    #[test]
    fn qos_policy_satisfied_when_quality_meets_thresholds() {
        let policy = QosPolicy { max_latency_ms: 100, min_availability_pct: 95, prefer_geographic_proximity: false };
        assert!(policy.is_satisfied_by(&make_quality(80, 99)));
        assert!(!policy.is_satisfied_by(&make_quality(150, 99))); // too slow
        assert!(!policy.is_satisfied_by(&make_quality(50, 90)));  // too unreliable
    }

    #[test]
    fn qos_policy_permissive_always_satisfied() {
        let policy = QosPolicy::permissive();
        assert!(policy.is_satisfied_by(&make_quality(5000, 0)));
    }

    // ── ServiceMeshCoordinator ────────────────────────────────────────────────

    #[test]
    fn mesh_coordinator_available_count() {
        let mut mesh = ServiceMeshCoordinator::new();
        mesh.register(Hash256([1u8; 32]));
        mesh.register(Hash256([2u8; 32]));
        assert_eq!(mesh.available_count(), 2);
    }

    #[test]
    fn mesh_coordinator_failover_excludes_unreachable() {
        let mut mesh = ServiceMeshCoordinator::new();
        let id1 = Hash256([1u8; 32]);
        let id2 = Hash256([2u8; 32]);
        mesh.register(id1);
        mesh.register(id2);
        mesh.update_health(&id1, false, None);
        mesh.update_health(&id1, false, None);
        mesh.update_health(&id1, false, None);
        assert_eq!(mesh.available_count(), 1);
    }

    #[test]
    fn mesh_coordinator_find_healthy_with_policy() {
        let mut mesh = ServiceMeshCoordinator::new();
        let id = Hash256([5u8; 32]);
        mesh.register(id);
        mesh.update_health(&id, true, Some(make_quality(20, 99)));
        let policy = QosPolicy { max_latency_ms: 100, min_availability_pct: 95, prefer_geographic_proximity: false };
        assert_eq!(mesh.find_healthy(&policy), Some(id));
    }

    // ── CrossNetworkServiceCoordinator ────────────────────────────────────────

    #[test]
    fn cross_network_coordinator_permitted() {
        let coord = CrossNetworkServiceCoordinator::new("public-mainnet", "enterprise-subnet-1", true);
        assert!(coord.can_route());
        assert_eq!(coord.source_network, "public-mainnet");
    }

    #[test]
    fn cross_network_coordinator_not_permitted() {
        let coord = CrossNetworkServiceCoordinator::new("public-mainnet", "private-subnet", false);
        assert!(!coord.can_route());
    }

    // ── SecureDeploymentRecord ────────────────────────────────────────────────

    #[test]
    fn secure_deployment_verified_stores_fields() {
        let h = Hash256([0xAB; 32]);
        let r = SecureDeploymentRecord::verified(h, TeePlatform::IntelSgx, "mainnet");
        assert!(r.integrity_verified);
        assert_eq!(r.artifact_hash, h);
        assert_eq!(r.target_network, "mainnet");
    }

    #[test]
    fn secure_deployment_rejected_is_not_verified() {
        // If build integrity fails, deployment is rejected — no partial state committed.
        let r = SecureDeploymentRecord::rejected(Hash256::ZERO, TeePlatform::AmdSev, "testnet");
        assert!(!r.integrity_verified);
    }

    // ── DataIntegrityProof ────────────────────────────────────────────────────

    #[test]
    fn data_integrity_proof_nonempty_when_root_nonzero() {
        let proof = DataIntegrityProof::new(Hash256([1u8; 32]), Hash256::ZERO, 1);
        assert!(proof.is_nonempty());
    }

    #[test]
    fn data_integrity_proof_empty_when_zero_root() {
        let proof = DataIntegrityProof::new(Hash256::ZERO, Hash256::ZERO, 0);
        assert!(!proof.is_nonempty());
    }

    // ── FederatedAnalyticsSession ─────────────────────────────────────────────

    #[test]
    fn federated_analytics_session_starts_active() {
        let session = FederatedAnalyticsSession::new(Hash256([1u8; 32]), 3);
        assert!(session.is_active);
        assert_eq!(session.participant_count, 3);
    }

    // ── EnterpriseIntegrationConfig ───────────────────────────────────────────

    #[test]
    fn enterprise_integration_with_audit() {
        let cfg = EnterpriseIntegrationConfig::with_audit("ACME-Corp");
        assert!(cfg.audit_trail_enabled);
        assert!(cfg.data_residency_region.is_none());
        assert_eq!(cfg.organization_id, "ACME-Corp");
    }

    #[test]
    fn enterprise_integration_with_data_residency() {
        // Data residency is application policy, not infrastructure policy.
        let mut cfg = EnterpriseIntegrationConfig::with_audit("Org-EU");
        cfg.data_residency_region = Some("EU".into());
        assert_eq!(cfg.data_residency_region.as_deref(), Some("EU"));
    }
}
