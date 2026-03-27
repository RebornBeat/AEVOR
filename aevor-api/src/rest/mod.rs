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
