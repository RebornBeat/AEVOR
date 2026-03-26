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
pub struct RestRouter;
pub struct RestHandler;

pub struct RestServer { config: RestConfig }
impl RestServer {
    pub fn new(config: RestConfig, _middleware: crate::middleware::MiddlewareStack, _router: crate::network_routing::MultiNetworkApi) -> Self { Self { config } }
    pub async fn serve(&self) -> crate::ApiResult<()> { Ok(()) }
}
