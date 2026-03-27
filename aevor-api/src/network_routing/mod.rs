//! Multi-network routing for API requests.

#[derive(Clone)]
pub struct MultiNetworkApi { pub network: String, pub backend: String }
impl MultiNetworkApi {
    /// Create a new multi-network API router.
    ///
    /// # Errors
    /// Currently always succeeds; the `Result` type allows future validation
    /// of the network name and backend endpoint format.
    pub fn new(network: &str, backend: &str) -> crate::ApiResult<Self> {
        Ok(Self { network: network.to_string(), backend: backend.to_string() })
    }
}

pub struct NetworkRouter;
pub struct NetworkSelector;
pub struct SubnetRouting;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_network_and_backend() {
        let api = MultiNetworkApi::new("testnet", "http://localhost:8731").unwrap();
        assert_eq!(api.network, "testnet");
        assert_eq!(api.backend, "http://localhost:8731");
    }

    #[test]
    fn new_mainnet() {
        let api = MultiNetworkApi::new("mainnet", "https://rpc.aevor.io").unwrap();
        assert_eq!(api.network, "mainnet");
    }

    #[test]
    fn clone_is_independent() {
        let a = MultiNetworkApi::new("devnet", "http://dev:8731").unwrap();
        let b = a.clone();
        assert_eq!(a.network, b.network);
        assert_eq!(a.backend, b.backend);
    }
}
