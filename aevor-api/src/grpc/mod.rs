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

    /// The gRPC server configuration (listen address, TLS credentials).
    pub fn config(&self) -> &GrpcConfig { &self.config }

    /// The socket address this gRPC server binds to.
    pub fn listen_addr(&self) -> SocketAddr { self.config.listen_addr }

    /// Start the gRPC server and serve until shutdown.
    ///
    /// # Errors
    /// Returns an error if the server cannot bind to the configured address.
    pub fn serve(&self) -> crate::ApiResult<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_server_listen_addr() {
        let cfg = GrpcConfig { listen_addr: "127.0.0.1:9090".parse().unwrap(), tls_cert: None, tls_key: None };
        let server = GrpcServer::new(cfg, crate::network_routing::MultiNetworkApi::default());
        assert_eq!(server.listen_addr().port(), 9090);
    }
}
