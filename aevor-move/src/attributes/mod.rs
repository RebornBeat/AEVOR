//! Move attribute annotations for AEVOR extensions.

use serde::{Deserialize, Serialize};
use aevor_core::privacy::PrivacyLevel;
use aevor_core::tee::TeePlatform;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyAttribute { pub level: PrivacyLevel }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeRequiredAttribute { pub platform: Option<TeePlatform> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossChainAttribute { pub target_chain: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MixedPrivacyAttribute { pub allowed_levels: Vec<PrivacyLevel> }

pub struct AttributeParser;
impl AttributeParser {
    pub fn parse_privacy(attrs: &[String]) -> Option<PrivacyAttribute> {
        attrs.iter().find(|a| a.starts_with("#[privacy"))
            .map(|_| PrivacyAttribute { level: PrivacyLevel::Private })
    }
}
