//! gRPC API server.
use std::net::SocketAddr;
#[derive(Clone, Debug)]
pub struct GrpcConfig { pub listen_addr: SocketAddr, pub tls_cert: Option<std::path::PathBuf>, pub tls_key: Option<std::path::PathBuf> }
pub struct AevorService;
pub struct TransactionService;
pub struct QueryService;
pub struct ConsensusService;
pub struct ValidatorService;

pub struct GrpcServer { config: GrpcConfig }
impl GrpcServer {
    pub fn new(config: GrpcConfig, _router: crate::network_routing::MultiNetworkApi) -> Self { Self { config } }
    pub async fn serve(&self) -> crate::ApiResult<()> { Ok(()) }
}
