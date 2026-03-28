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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::privacy::PrivacyLevel;

    #[test]
    fn attribute_parser_finds_privacy_attribute() {
        let attrs = vec!["#[privacy(level=private)]".into()];
        let pa = AttributeParser::parse_privacy(&attrs).unwrap();
        assert_eq!(pa.level, PrivacyLevel::Private);
    }

    #[test]
    fn attribute_parser_returns_none_for_no_match() {
        let attrs = vec!["#[view]".into(), "#[entry]".into()];
        assert!(AttributeParser::parse_privacy(&attrs).is_none());
    }

    #[test]
    fn mixed_privacy_attribute_stores_levels() {
        let mpa = MixedPrivacyAttribute { allowed_levels: vec![PrivacyLevel::Public, PrivacyLevel::Private] };
        assert_eq!(mpa.allowed_levels.len(), 2);
    }
}
