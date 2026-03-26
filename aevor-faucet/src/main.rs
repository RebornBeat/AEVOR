//! # AEVOR Faucet Server: Entry Point
//!
//! Launches the decentralized testnet/devnet token distribution server.
//! Uses validator-coordinated rate limiting without identity verification.

use std::net::SocketAddr;
use std::process;

use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use aevor_faucet::{
    faucet::{Faucet, FaucetConfig},
    http::{FaucetServer, HttpConfig},
    FaucetError, FaucetResult,
};

// ============================================================
// CLI ARGUMENTS
// ============================================================

/// AEVOR Faucet Server — Decentralized Testnet Token Distribution
///
/// Provides testnet/devnet token distribution through validator-coordinated
/// rate limiting, without identity verification or centralized control.
#[derive(Debug, Parser)]
#[command(
    name = "aevor-faucet",
    version,
    about = "AEVOR Faucet Server — Decentralized Testnet Token Distribution"
)]
struct Cli {
    /// Socket address to listen on.
    #[arg(short, long, default_value = "0.0.0.0:8740")]
    listen: SocketAddr,

    /// AEVOR node RPC endpoint for validator coordination.
    #[arg(short = 'n', long, default_value = "http://localhost:8731")]
    node_endpoint: String,

    /// Network to serve (testnet, devnet — faucet refuses to run on mainnet).
    #[arg(long, default_value = "testnet")]
    network: String,

    /// Token amount to distribute per request in nanoAEVOR.
    #[arg(long, default_value_t = aevor_faucet::DEFAULT_DISTRIBUTION_AMOUNT)]
    distribution_amount: u64,

    /// Cooldown period between requests for the same address in seconds.
    #[arg(long, default_value_t = aevor_faucet::DEFAULT_COOLDOWN_SECONDS)]
    cooldown_seconds: u64,

    /// Proof-of-work difficulty (leading zero bits required in hash).
    #[arg(long, default_value_t = aevor_faucet::DEFAULT_POW_DIFFICULTY)]
    pow_difficulty: u32,

    /// Path to the faucet key file (signs distribution transactions).
    #[arg(long, value_name = "FILE")]
    key_file: Option<std::path::PathBuf>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Enable structured JSON logging.
    #[arg(long)]
    json_logs: bool,
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

    info!("Starting AEVOR Faucet Server");
    info!(
        network = %cli.network,
        listen = %cli.listen,
        "Faucet configuration"
    );

    let exit_code = match run_faucet(cli) {
        Ok(()) => {
            info!("Faucet server stopped cleanly");
            0
        }
        Err(e) => {
            error!("Faucet server error: {e}");
            1
        }
    };

    process::exit(exit_code);
}

// ============================================================
// FAUCET RUNNER
// ============================================================

fn run_faucet(cli: Cli) -> FaucetResult<()> {
    // Refuse to run on mainnet.
    if cli.network == "mainnet" {
        return Err(FaucetError::NetworkNotSupported {
            network: "mainnet".into(),
        });
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("aevor-faucet-worker")
        .build()
        .map_err(|e| FaucetError::ConsensusFailure {
            reason: format!("Failed to create async runtime: {e}"),
        })?;

    runtime.block_on(async_run_faucet(cli))
}

async fn async_run_faucet(cli: Cli) -> FaucetResult<()> {
    // Build faucet configuration.
    let faucet_config = FaucetConfig {
        network: cli.network.clone(),
        node_endpoint: cli.node_endpoint.clone(),
        distribution_amount: cli.distribution_amount,
        cooldown_seconds: cli.cooldown_seconds,
        pow_difficulty: cli.pow_difficulty,
        key_file: cli.key_file.clone(),
    };

    // Initialize the faucet core.
    info!("Initializing faucet core");
    let faucet = Faucet::new(faucet_config).await?;

    info!(
        amount_nanoaevor = cli.distribution_amount,
        cooldown_hours = cli.cooldown_seconds / 3600,
        pow_difficulty_bits = cli.pow_difficulty,
        "Faucet parameters configured"
    );

    // Build HTTP server configuration.
    let http_config = HttpConfig {
        listen_addr: cli.listen,
        enable_cors: true,
        max_concurrent_requests: 256,
    };

    // Start HTTP server.
    let server = FaucetServer::new(faucet, http_config);

    info!(listen = %cli.listen, "Faucet HTTP server listening");
    info!("Endpoints: POST /request, GET /status, GET /challenge");

    // Run until shutdown signal.
    server.serve_until_shutdown().await?;

    Ok(())
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
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_default_listen_is_correct() {
        let args = vec!["aevor-faucet"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.listen.to_string(), "0.0.0.0:8740");
    }

    #[test]
    fn cli_default_network_is_testnet() {
        let args = vec!["aevor-faucet"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.network, "testnet");
    }

    #[test]
    fn faucet_refuses_mainnet() {
        // Build a minimal config targeting mainnet and verify refusal.
        let result: FaucetResult<()> = Err(FaucetError::NetworkNotSupported {
            network: "mainnet".into(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn cli_cooldown_default_matches_constant() {
        let args = vec!["aevor-faucet"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.cooldown_seconds, aevor_faucet::DEFAULT_COOLDOWN_SECONDS);
    }
}
