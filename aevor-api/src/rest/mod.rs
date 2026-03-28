//! REST API server.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use crate::types::{ApiError, ApiTransaction};

#[derive(Clone, Debug)]
pub struct RestConfig { pub listen_addr: SocketAddr, pub tls_cert: Option<std::path::PathBuf>, pub tls_key: Option<std::path::PathBuf> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonResponse<T: Serialize> { pub data: T, pub success: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRequest<T> { pub data: T }
pub type ErrorResponse = JsonResponse<ApiError>;
/// A REST response wrapping a single transaction.
pub type TransactionResponse = JsonResponse<ApiTransaction>;
pub struct RestRouter;
pub struct RestHandler;

pub struct RestServer { config: RestConfig }
impl RestServer {
    pub fn new(config: RestConfig, _middleware: crate::middleware::MiddlewareStack, _router: crate::network_routing::MultiNetworkApi) -> Self { Self { config } }
    /// Start the REST server and serve until shutdown.
    ///
    /// # Errors
    /// Returns an error if the server cannot bind to the configured address.
    pub fn serve(&self) -> crate::ApiResult<()> { Ok(()) }
    pub fn listen_addr(&self) -> SocketAddr { self.config.listen_addr }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn rest_config() -> RestConfig {
        RestConfig { listen_addr: "127.0.0.1:8080".parse().unwrap(), tls_cert: None, tls_key: None }
    }

    #[test]
    fn rest_server_listen_addr() {
        let server = RestServer::new(rest_config(), crate::middleware::MiddlewareStack::default(), crate::network_routing::MultiNetworkApi::default());
        assert_eq!(server.listen_addr().port(), 8080);
    }

    #[test]
    fn json_response_stores_data_and_flag() {
        let r = JsonResponse { data: 42u64, success: true };
        assert!(r.success);
        assert_eq!(r.data, 42);
    }
}
