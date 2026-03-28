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

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::privacy::PrivacyLevel;

    #[test]
    fn privacy_annotation_stores_level_and_field() {
        let ann = PrivacyAnnotation { level: PrivacyLevel::Private, field: "medical_data".into() };
        assert_eq!(ann.level, PrivacyLevel::Private);
        assert_eq!(ann.field, "medical_data");
    }

    #[test]
    fn privacy_annotation_public_field() {
        let ann = PrivacyAnnotation { level: PrivacyLevel::Public, field: "record_type".into() };
        assert_eq!(ann.level, PrivacyLevel::Public);
    }

    #[test]
    fn privacy_levels_are_ordered() {
        // Private > Protected > Public — higher means more confidential
        assert!(PrivacyLevel::Private > PrivacyLevel::Public);
    }
}
