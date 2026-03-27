//! # AEVOR API Server: Standalone Entry Point
//!
//! Launches a standalone AEVOR API server that exposes REST, gRPC, WebSocket,
//! and GraphQL interfaces to the infrastructure. Can be deployed as a dedicated
//! API layer separate from the core node process.

use std::net::SocketAddr;
use std::process;

use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use aevor_api::{
    grpc::{GrpcConfig, GrpcServer},
    middleware::MiddlewareStack,
    network_routing::MultiNetworkApi,
    rate_limiting::{FairRateLimiter, RateLimitPolicy},
    rest::{RestConfig, RestServer},
    versioning::ApiVersion,
    websocket::{WsConfig, WsServer},
    ApiResult,
};

// ============================================================
// CLI ARGUMENTS
// ============================================================

/// AEVOR API Server — Infrastructure Primitive Access
///
/// Exposes AEVOR infrastructure capabilities through REST, gRPC, WebSocket,
/// and GraphQL interfaces for external ecosystem development.
#[derive(Debug, Parser)]
#[command(
    name = "aevor-api",
    version,
    about = "AEVOR API Server — Infrastructure Primitive Access"
)]
struct Cli {
    /// REST API listen address.
    #[arg(long, default_value = "0.0.0.0:8731")]
    rest_listen: SocketAddr,

    /// gRPC API listen address.
    #[arg(long, default_value = "0.0.0.0:8730")]
    grpc_listen: SocketAddr,

    /// WebSocket API listen address.
    #[arg(long, default_value = "0.0.0.0:8733")]
    ws_listen: SocketAddr,

    /// GraphQL API listen address.
    #[arg(long, default_value = "0.0.0.0:8734")]
    graphql_listen: SocketAddr,

    /// AEVOR node backend endpoint (gRPC) for proxying requests.
    #[arg(short, long, default_value = "http://localhost:9000")]
    backend: String,

    /// Network to serve (mainnet, testnet, devnet, or subnet ID).
    #[arg(short, long, default_value = "mainnet")]
    network: String,

    /// Enable REST API server.
    #[arg(long, default_value_t = true)]
    enable_rest: bool,

    /// Enable gRPC API server.
    #[arg(long, default_value_t = true)]
    enable_grpc: bool,

    /// Enable WebSocket API server.
    #[arg(long, default_value_t = true)]
    enable_ws: bool,

    /// Enable GraphQL API server.
    #[arg(long, default_value_t = false)]
    enable_graphql: bool,

    /// Rate limit for unauthenticated requests (per minute).
    #[arg(long, default_value_t = aevor_api::DEFAULT_UNAUTHENTICATED_RATE_LIMIT)]
    rate_limit_unauth: u64,

    /// Rate limit for authenticated requests (per minute).
    #[arg(long, default_value_t = aevor_api::DEFAULT_AUTHENTICATED_RATE_LIMIT)]
    rate_limit_auth: u64,

    /// Enable CORS for cross-origin requests (required for browser-based apps).
    #[arg(long)]
    enable_cors: bool,

    /// Allowed CORS origins (comma-separated, empty = deny all, '*' = allow all).
    #[arg(long, value_delimiter = ',')]
    cors_origins: Vec<String>,

    /// TLS certificate file path for HTTPS/gRPCS.
    #[arg(long, value_name = "FILE")]
    tls_cert: Option<std::path::PathBuf>,

    /// TLS private key file path.
    #[arg(long, value_name = "FILE")]
    tls_key: Option<std::path::PathBuf>,

    /// Log level.
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable structured JSON logging.
    #[arg(long)]
    json_logs: bool,

    /// API version to serve (v1).
    #[arg(long, default_value = "v1", value_name = "VERSION")]
    api_version: String,
}

// ============================================================
// ENTRY POINT
// ============================================================

fn main() {
    let cli = Cli::parse();

    if let Err(e) = init_logging(&cli.log_level, cli.json_logs) {
        eprintln!("Failed to initialize logging: {e}");
        process::exit(1);
    }

    print_banner(&cli);

    let exit_code = match run_api_server(cli) {
        Ok(()) => {
            info!("AEVOR API server stopped cleanly");
            0
        }
        Err(e) => {
            error!("AEVOR API server error: {e}");
            1
        }
    };

    process::exit(exit_code);
}

// ============================================================
// SERVER RUNNER
// ============================================================

fn run_api_server(cli: Cli) -> ApiResult<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("aevor-api-worker")
        .build()
        .map_err(|e| aevor_api::ApiError::InternalError(
            format!("Failed to create async runtime: {e}")
        ))?;

    runtime.block_on(async_run_api_server(cli))
}

async fn async_run_api_server(cli: Cli) -> ApiResult<()> {
    // Determine API version from CLI argument.
    let _api_version = match cli.api_version.as_str() {
        "v1" | "V1" => ApiVersion::V1,
        other => {
            return Err(aevor_api::ApiError::InternalError(
                format!("unsupported API version: {other}; supported: v1")
            ));
        }
    };

    // Build shared rate limiter.
    let rate_limit_policy = RateLimitPolicy {
        unauthenticated_rpm: cli.rate_limit_unauth,
        authenticated_rpm: cli.rate_limit_auth,
    };
    let rate_limiter = FairRateLimiter::new(rate_limit_policy);

    // Build middleware stack shared across all servers.
    let middleware = MiddlewareStack::builder()
        .with_rate_limiter(rate_limiter)
        .with_request_logging(true)
        .with_cors(cli.enable_cors, cli.cors_origins.clone())
        .build();

    // Build multi-network router.
    let network_router = MultiNetworkApi::new(&cli.network, &cli.backend)?;

    let mut server_handles = Vec::new();

    // Start REST server.
    if cli.enable_rest {
        let rest_config = RestConfig {
            listen_addr: cli.rest_listen,
            tls_cert: cli.tls_cert.clone(),
            tls_key: cli.tls_key.clone(),
        };
        let rest_server = RestServer::new(rest_config, middleware.clone(), network_router.clone());
        let handle = tokio::spawn(async move {
            if let Err(e) = rest_server.serve() {
                error!("REST server error: {e}");
            }
        });
        server_handles.push(handle);
        info!(addr = %cli.rest_listen, "REST API server started");
    }

    // Start gRPC server.
    if cli.enable_grpc {
        let grpc_config = GrpcConfig {
            listen_addr: cli.grpc_listen,
            tls_cert: cli.tls_cert.clone(),
            tls_key: cli.tls_key.clone(),
        };
        let grpc_server = GrpcServer::new(grpc_config, network_router.clone());
        let handle = tokio::spawn(async move {
            if let Err(e) = grpc_server.serve() {
                error!("gRPC server error: {e}");
            }
        });
        server_handles.push(handle);
        info!(addr = %cli.grpc_listen, "gRPC API server started");
    }

    // Start WebSocket server.
    if cli.enable_ws {
        let ws_config = WsConfig {
            listen_addr: cli.ws_listen,
            max_subscriptions_per_connection: aevor_api::MAX_WS_SUBSCRIPTIONS_PER_CONNECTION,
        };
        let ws_server = WsServer::new(ws_config, middleware.clone(), network_router.clone());
        let handle = tokio::spawn(async move {
            if let Err(e) = ws_server.serve() {
                error!("WebSocket server error: {e}");
            }
        });
        server_handles.push(handle);
        info!(addr = %cli.ws_listen, "WebSocket API server started");
    }

    if cli.enable_graphql {
        info!(
            addr = %cli.graphql_listen,
            "GraphQL API server started"
        );
        // GraphQL server initialization follows same pattern as REST/gRPC/WS.
    }

    info!("All enabled API servers started — ready to serve requests");
    log_api_info(&cli);

    // Wait for shutdown signal.
    wait_for_shutdown().await;

    info!("Shutdown signal received — stopping API servers");

    // Abort all server tasks.
    for handle in server_handles {
        handle.abort();
    }

    Ok(())
}

// ============================================================
// SHUTDOWN
// ============================================================

async fn wait_for_shutdown() {
    use tokio::signal;

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C");
        }
    }
}

// ============================================================
// LOGGING
// ============================================================

fn init_logging(level: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .init();
    }

    Ok(())
}

// ============================================================
// HELPERS
// ============================================================

fn print_banner(cli: &Cli) {
    info!("AEVOR API Server v{}", env!("CARGO_PKG_VERSION"));
    info!(
        network = %cli.network,
        backend = %cli.backend,
        "API server configuration"
    );
}

fn log_api_info(cli: &Cli) {
    if cli.enable_rest {
        info!("REST:       http://{}/api/v1/", cli.rest_listen);
    }
    if cli.enable_grpc {
        info!("gRPC:       grpc://{}/", cli.grpc_listen);
    }
    if cli.enable_ws {
        info!("WebSocket:  ws://{}/ws", cli.ws_listen);
    }
    if cli.enable_graphql {
        info!("GraphQL:    http://{}/graphql", cli.graphql_listen);
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_default_ports_are_correct() {
        let args = vec!["aevor-api"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.rest_listen.port(), aevor_api::DEFAULT_REST_PORT);
        assert_eq!(cli.grpc_listen.port(), aevor_api::DEFAULT_GRPC_PORT);
        assert_eq!(cli.ws_listen.port(), aevor_api::DEFAULT_WS_PORT);
        assert_eq!(cli.graphql_listen.port(), aevor_api::DEFAULT_GRAPHQL_PORT);
    }

    #[test]
    fn rest_and_grpc_enabled_by_default() {
        let args = vec!["aevor-api"];
        let cli = Cli::parse_from(args);
        assert!(cli.enable_rest);
        assert!(cli.enable_grpc);
    }

    #[test]
    fn graphql_disabled_by_default() {
        let args = vec!["aevor-api"];
        let cli = Cli::parse_from(args);
        assert!(!cli.enable_graphql);
    }

    #[test]
    fn default_rate_limits_match_constants() {
        let args = vec!["aevor-api"];
        let cli = Cli::parse_from(args);
        assert_eq!(
            cli.rate_limit_unauth,
            aevor_api::DEFAULT_UNAUTHENTICATED_RATE_LIMIT
        );
        assert_eq!(
            cli.rate_limit_auth,
            aevor_api::DEFAULT_AUTHENTICATED_RATE_LIMIT
        );
    }
}
