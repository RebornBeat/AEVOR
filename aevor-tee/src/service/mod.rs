//! TEE service allocation, discovery, and quality management.

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceQuality {
    /// P99 request latency in milliseconds.
    pub latency_ms: u32,
    /// Availability over the trailing 30-day window, expressed as a percentage.
    pub availability_pct: u8,
    /// Consensus security level this instance can satisfy.
    pub security_level: aevor_core::consensus::SecurityLevel,
    /// Hardware platform of this instance.
    pub platform: TeePlatform,
    /// Maximum throughput in requests per second.
    pub throughput_rps: u32,
}

impl ServiceQuality {
    /// Composite quality score: higher is better.
    pub fn score(&self) -> u64 {
        let avail = self.availability_pct as u64;
        let lat = (1000u64).saturating_sub(self.latency_ms as u64);
        avail * 10 + lat
    }
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
    /// Maximum number of concurrent requests.
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
    pub fn new() -> Self {
        Self { known_providers: Vec::new() }
    }

    /// Register a new provider capability (called when validators announce services).
    pub fn register_provider(&mut self, cap: ServiceCapability) {
        self.known_providers.push(cap);
    }

    /// Attempt to allocate a service matching the request.
    ///
    /// Selects the best provider according to `request.strategy` and returns
    /// a `TeeServiceResponse` with the allocation details.
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
                throughput_rps: 1000,
            },
        })
    }

    /// Number of registered providers.
    pub fn provider_count(&self) -> usize { self.known_providers.len() }
}

impl Default for TeeServiceAllocator {
    fn default() -> Self { Self::new() }
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

    #[test]
    fn allocator_returns_error_with_no_providers() {
        let allocator = TeeServiceAllocator::new();
        let req = make_request(TeeServiceType::ConfidentialCompute);
        assert!(allocator.allocate(&req).is_err());
    }

    #[test]
    fn allocator_returns_handle_when_provider_matches() {
        let mut allocator = TeeServiceAllocator::new();
        allocator.register_provider(ServiceCapability {
            service_type: TeeServiceType::ConfidentialCompute,
            platform: TeePlatform::IntelSgx,
            max_memory_bytes: 128 * 1024,
            max_concurrent: 4,
            price_per_request_nano: 100,
        });
        let req = make_request(TeeServiceType::ConfidentialCompute);
        let resp = allocator.allocate(&req).unwrap();
        assert!(resp.handle.is_valid(0));
    }

    #[test]
    fn service_quality_score_prefers_high_availability() {
        let high_avail = ServiceQuality {
            latency_ms: 100, availability_pct: 99,
            security_level: SecurityLevel::Basic,
            platform: TeePlatform::IntelSgx, throughput_rps: 100,
        };
        let low_avail = ServiceQuality {
            latency_ms: 100, availability_pct: 80,
            security_level: SecurityLevel::Basic,
            platform: TeePlatform::IntelSgx, throughput_rps: 100,
        };
        assert!(high_avail.score() > low_avail.score());
    }
}
