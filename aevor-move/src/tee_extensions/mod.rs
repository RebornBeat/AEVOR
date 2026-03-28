//! Move language TEE service access extensions.

use serde::{Deserialize, Serialize};
use aevor_core::tee::TeePlatform;

pub struct TeeServiceModule;
pub struct ConfidentialCompute;
pub struct SecureExecution;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeContext { pub platform: TeePlatform, pub nonce: [u8; 32] }
pub type MoveTeeContext = TeeContext;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeAttestation { pub platform: TeePlatform, pub hash: aevor_core::primitives::Hash256 }
pub type MoveTeeAttestation = TeeAttestation;

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::tee::TeePlatform;
    use aevor_core::primitives::Hash256;

    #[test]
    fn tee_context_stores_platform_and_nonce() {
        let ctx = TeeContext { platform: TeePlatform::AmdSev, nonce: [0xABu8; 32] };
        assert_eq!(ctx.platform, TeePlatform::AmdSev);
        assert_eq!(ctx.nonce, [0xABu8; 32]);
    }

    #[test]
    fn tee_attestation_stores_platform_and_hash() {
        let att = TeeAttestation { platform: TeePlatform::AwsNitro, hash: Hash256([1u8;32]) };
        assert_eq!(att.platform, TeePlatform::AwsNitro);
    }
}
