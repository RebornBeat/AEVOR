//! # AEVOR Node: Primary Node Process Entry Point
//!
//! This binary launches an AEVOR node in the requested mode (validator, full,
//! archive, or light) and orchestrates all subsystems through their complete
//! lifecycle from initialization to graceful shutdown.

use std::process;

use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use node::{
    config::NodeConfig,
    orchestrator::{NodeOrchestrator, OrchestratorConfig},
    process::{install_signal_handlers, SignalReceiver},
    NodeError, NodeResult,
};

// ============================================================
// CLI ARGUMENT STRUCTURE
// ============================================================

/// AEVOR Node — Revolutionary Blockchain Infrastructure
///
/// Genuine blockchain trilemma transcendence through mathematical coordination:
/// 200,000+ TPS sustained, mathematical security through TEE attestation,
/// and progressive finality from 20ms to <1s based on security requirements.
#[derive(Debug, Parser)]
#[command(
    name = "aevor-node",
    version,
    about = "AEVOR Node — Revolutionary Blockchain Infrastructure",
    long_about = None,
)]
struct Cli {
    /// Path to the node configuration file.
    ///
    /// Defaults to ~/.aevor/config.toml if not specified.
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<std::path::PathBuf>,

    /// Override the data directory for blockchain state storage.
    #[arg(short, long, value_name = "DIR", global = true)]
    data_dir: Option<std::path::PathBuf>,

    /// Override the log level (trace, debug, info, warn, error).
    #[arg(short, long, value_name = "LEVEL", global = true, default_value = "info")]
    log_level: String,

    /// Enable structured JSON logging (for production deployments).
    #[arg(long, global = true)]
    json_logs: bool,

    /// Node operating mode.
    #[command(subcommand)]
    mode: Option<NodeMode>,
}

/// Node operating modes.
#[derive(Debug, Subcommand)]
enum NodeMode {
    /// Run as a validator node — participates in consensus and provides TEE services.
    ///
    /// Requires a registered validator key and configured TEE platform.
    /// Earns consensus and TEE service rewards.
    Validator {
        /// Path to the validator signing key file.
        #[arg(short, long, value_name = "FILE")]
        key_file: Option<std::path::PathBuf>,

        /// TEE platform to use (sgx, sev, trustzone, keystone, nitro, auto).
        #[arg(long, default_value = "auto")]
        tee_platform: String,
    },

    /// Run as a full node — stores complete state, serves API, no consensus.
    Full {
        /// Enable the REST API server.
        #[arg(long, default_value = "true")]
        enable_api: bool,
    },

    /// Run as an archive node — stores complete historical state.
    Archive {
        /// Maximum archive storage in gigabytes (0 = unlimited).
        #[arg(long, default_value = "0")]
        max_storage_gb: u64,
    },

    /// Run as a light node — verifies headers only, minimal resources.
    Light {
        /// Trusted checkpoint hash to start syncing from.
        #[arg(long)]
        checkpoint: Option<String>,
    },
}

// ============================================================
// ENTRY POINT
// ============================================================

fn main() {
    // Parse command-line arguments first so we can use log-level before anything else.
    let cli = Cli::parse();

    // Initialize logging subsystem.
    if let Err(e) = init_logging(&cli.log_level, cli.json_logs) {
        eprintln!("Failed to initialize logging: {e}");
        process::exit(1);
    }

    // Print startup banner.
    print_banner();

    // Run the async runtime.
    let exit_code = match run_node(cli) {
        Ok(()) => {
            info!("AEVOR node exited cleanly");
            0
        }
        Err(e) => {
            error!("AEVOR node exited with error: {e}");
            1
        }
    };

    process::exit(exit_code);
}

// ============================================================
// NODE RUNNER
// ============================================================

fn run_node(cli: Cli) -> NodeResult<()> {
    // Build the async runtime.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("aevor-worker")
        .build()
        .map_err(|e| NodeError::InitializationFailed {
            subsystem: "tokio-runtime".into(),
            reason: e.to_string(),
        })?;

    runtime.block_on(async_run_node(cli))
}

async fn async_run_node(cli: Cli) -> NodeResult<()> {
    // Load configuration.
    info!("Loading node configuration");
    let node_config = load_config(&cli)?;

    // Build orchestrator configuration from CLI + config file.
    let orch_config = build_orchestrator_config(&cli, node_config)?;

    // Install OS signal handlers (SIGTERM, SIGINT, SIGHUP).
    let signal_rx = install_signal_handlers().map_err(|e| NodeError::InitializationFailed {
        subsystem: "signal-handler".into(),
        reason: e.to_string(),
    })?;

    // Create and start the node orchestrator.
    info!(
        mode = ?determine_mode(&cli.mode),
        "Starting AEVOR node orchestration"
    );

    let orchestrator = NodeOrchestrator::new(orch_config)?;
    let node_handle = orchestrator.start()?;

    info!("AEVOR node started successfully — all subsystems operational");
    log_node_info(&node_handle);

    // Wait for shutdown signal.
    wait_for_shutdown(signal_rx).await;

    info!("Shutdown signal received — initiating graceful shutdown");
    node_handle.shutdown()?;

    info!("All subsystems stopped cleanly");
    Ok(())
}

// ============================================================
// CONFIGURATION LOADING
// ============================================================

fn load_config(cli: &Cli) -> NodeResult<NodeConfig> {
    use node::config::NodeConfig;

    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(default_config_path);

    if config_path.exists() {
        info!(path = %config_path.display(), "Loading configuration file");
        NodeConfig::from_file(&config_path).map_err(|e| NodeError::InvalidConfiguration {
            node_type: "node".into(),
            reason: format!("Failed to load config from {}: {e}", config_path.display()),
        })
    } else {
        warn!(
            path = %config_path.display(),
            "Config file not found — using defaults"
        );
        Ok(NodeConfig::default())
    }
}

fn build_orchestrator_config(
    cli: &Cli,
    mut node_config: NodeConfig,
) -> NodeResult<OrchestratorConfig> {
    // Apply CLI overrides to configuration.
    if let Some(ref data_dir) = cli.data_dir {
        node_config.data_dir = data_dir.clone();
    }

    // Determine node mode from CLI subcommand.
    let mode = determine_mode(&cli.mode);

    OrchestratorConfig::from_node_config(node_config, mode).map_err(|e| {
        NodeError::InvalidConfiguration {
            node_type: format!("{mode:?}"),
            reason: e.to_string(),
        }
    })
}

fn determine_mode(mode: &Option<NodeMode>) -> node::orchestrator::NodeMode {
    match mode {
        Some(NodeMode::Validator { .. }) => node::orchestrator::NodeMode::Validator,
        Some(NodeMode::Full { .. }) => node::orchestrator::NodeMode::Full,
        Some(NodeMode::Archive { .. }) => node::orchestrator::NodeMode::Archive,
        Some(NodeMode::Light { .. }) => node::orchestrator::NodeMode::Light,
        None => node::orchestrator::NodeMode::Full, // Default to full node
    }
}

// ============================================================
// SHUTDOWN COORDINATION
// ============================================================

async fn wait_for_shutdown(mut signal_rx: SignalReceiver) {
    let reason = signal_rx.recv().await.unwrap_or_else(|| "channel closed".into());
    info!(reason = %reason, "Shutdown triggered");
}

// ============================================================
// LOGGING INITIALIZATION
// ============================================================

fn init_logging(level: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    if json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_target(true))
            .init();
    }

    Ok(())
}

// ============================================================
// HELPERS
// ============================================================

fn print_banner() {
    info!("╔══════════════════════════════════════════════════════╗");
    info!("║           AEVOR — Revolutionary Blockchain            ║");
    info!("║     200,000+ TPS | Mathematical Security | TEE       ║");
    info!("╚══════════════════════════════════════════════════════╝");
    info!(version = env!("CARGO_PKG_VERSION"), "AEVOR Node starting");
}

fn log_node_info(handle: &node::orchestrator::NodeHandle) {
    info!(
        peer_id = %handle.peer_id(),
        network = %handle.network_id(),
        mode = %handle.mode(),
        tee_platforms = ?handle.active_tee_platforms(),
        "Node information"
    );
}

fn default_config_path() -> std::path::PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    path.push(".aevor");
    path.push("config.toml");
    path
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_validator_mode() {
        let args = vec!["aevor-node", "validator", "--tee-platform", "auto"];
        let cli = Cli::parse_from(args);
        assert!(matches!(cli.mode, Some(NodeMode::Validator { .. })));
    }

    #[test]
    fn cli_parses_full_mode() {
        let args = vec!["aevor-node", "full"];
        let cli = Cli::parse_from(args);
        assert!(matches!(cli.mode, Some(NodeMode::Full { .. })));
    }

    #[test]
    fn cli_defaults_to_info_log_level() {
        let args = vec!["aevor-node"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.log_level, "info");
    }

    #[test]
    fn default_mode_is_full_when_omitted() {
        let mode = determine_mode(&None);
        assert!(matches!(mode, node::orchestrator::NodeMode::Full));
    }

    #[test]
    fn default_config_path_ends_with_config_toml() {
        let path = default_config_path();
        assert!(path.to_string_lossy().ends_with("config.toml"));
    }

    #[test]
    fn default_config_path_contains_aevor() {
        let path = default_config_path();
        assert!(path.to_string_lossy().contains(".aevor"));
    }

    #[test]
    fn cli_parses_archive_mode() {
        let args = vec!["aevor-node", "archive"];
        let cli = Cli::parse_from(args);
        assert!(matches!(cli.mode, Some(NodeMode::Archive { .. })));
    }
}
