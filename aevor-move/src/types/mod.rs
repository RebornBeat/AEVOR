//! AEVOR-extended Move types.

use serde::{Deserialize, Serialize};
use aevor_core::privacy::PrivacyLevel;
use aevor_core::tee::TeePlatform;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyType { pub inner: String, pub level: PrivacyLevel }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeType { pub inner: String, pub platform: Option<TeePlatform> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationType { pub inner: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossChainType { pub inner: String, pub chain: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AevorMoveType {
    Privacy(PrivacyType), Tee(TeeType), Attestation(AttestationType),
    CrossChain(CrossChainType), Standard(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevor_core::privacy::PrivacyLevel;
    use aevor_core::tee::TeePlatform;

    #[test]
    fn privacy_type_stores_level() {
        let pt = PrivacyType { inner: "u64".into(), level: PrivacyLevel::Private };
        assert_eq!(pt.level, PrivacyLevel::Private);
    }

    #[test]
    fn tee_type_optional_platform() {
        let tt = TeeType { inner: "vector<u8>".into(), platform: Some(TeePlatform::IntelSgx) };
        assert_eq!(tt.platform, Some(TeePlatform::IntelSgx));
        let no_plat = TeeType { inner: "bool".into(), platform: None };
        assert!(no_plat.platform.is_none());
    }

    #[test]
    fn aevor_move_type_standard_variant() {
        let t = AevorMoveType::Standard("u64".into());
        assert!(matches!(t, AevorMoveType::Standard(_)));
    }
}
