//! Privacy-filtered API responses.
use serde::{Deserialize, Serialize};
use aevor_core::privacy::PrivacyLevel;
pub struct PrivacyAwareSerializer;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyFilteredResponse<T: Serialize> { pub data: Option<T>, pub privacy_level: PrivacyLevel }
pub struct AuthorizedView;
pub struct SelectiveDisclosureResponse;
