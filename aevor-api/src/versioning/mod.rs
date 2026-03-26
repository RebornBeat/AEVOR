//! API versioning.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiVersion { V1 }
impl ApiVersion {
    pub fn path_prefix(&self) -> &'static str { match self { Self::V1 => "/api/v1" } }
}
