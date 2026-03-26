//! Move language privacy annotation extensions.

use serde::{Deserialize, Serialize};
use aevor_core::privacy::PrivacyLevel;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyAnnotation { pub level: PrivacyLevel, pub field: String }

pub struct PrivateData;
pub struct ProtectedData;
pub struct PublicData;
pub struct MixedPrivacyModule;
pub struct SelectiveDisclosureModule;
