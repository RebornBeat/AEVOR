//! Multi-network routing for API requests.

#[derive(Clone)]
pub struct MultiNetworkApi { pub network: String, pub backend: String }
impl MultiNetworkApi {
    pub fn new(network: &str, backend: &str) -> crate::ApiResult<Self> {
        Ok(Self { network: network.to_string(), backend: backend.to_string() })
    }
}

pub struct NetworkRouter;
pub struct NetworkSelector;
pub struct SubnetRouting;
