//! Privacy-preserving DNS.
use serde::{Deserialize, Serialize};
pub struct PrivateResolver;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialQuery { pub encrypted_name: Vec<u8> }
pub struct ResolutionPrivacy;
pub struct AntiSurveillanceDns;
pub struct TeeEncryptedResolution;
