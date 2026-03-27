//! # AEVOR CLI: Command-Line Administration Tool
//!
//! Entry point for the `aevor` command-line tool that provides infrastructure
//! administration capabilities for node operators, validators, and network administrators.

use std::process;

use clap::{Parser, Subcommand};
use tracing::{error};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use aevor_cli::{
    args::GlobalArgs,
    config::CliConfig as ConfigCmd,
    context::{CliContext, NetworkContext},
    governance::GovernanceCommand,
    keys::KeysCommand,
    network::NetworkCommand,
    node::NodeCommand,
    output::{OutputFormat, OutputWriter},
    status::StatusCommand,
    tee::TeeCommand,
    validator::ValidatorCommand,
    CliError, CliResult,
};

// ============================================================
// TOP-LEVEL CLI STRUCTURE
// ============================================================

/// AEVOR — Infrastructure Administration Tool
///
/// Manages AEVOR node operations, validator registration, network administration,
/// governance participation, and TEE configuration.
#[derive(Debug, Parser)]
#[command(
    name = "aevor",
    version,
    about = "AEVOR — Infrastructure Administration",
    long_about = "
AEVOR infrastructure administration tool for node operators and validators.

EXAMPLES:
  aevor node start --mode validator
  aevor validator register --stake 100000
  aevor governance propose --type parameter-change
  aevor status --network mainnet
",
)]
struct Cli {
    /// AEVOR RPC endpoint (default: http://localhost:8731).
    #[arg(short, long, value_name = "URL", global = true)]
    endpoint: Option<String>,

    /// Network to operate on (mainnet, testnet, devnet, or subnet ID).
    #[arg(short, long, value_name = "NETWORK", global = true, default_value = "mainnet")]
    network: String,

    /// Output format (human, json, table).
    #[arg(short = 'f', long, value_name = "FORMAT", global = true, default_value = "human")]
    output: OutputFormat,

    /// Suppress informational output (errors still shown).
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Enable verbose debug output.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Path to configuration file.
    #[arg(long, value_name = "FILE", global = true)]
    config: Option<std::path::PathBuf>,

    /// Skip confirmation prompts (use with caution).
    #[arg(long = "yes", short = 'y', global = true)]
    no_confirm: bool,

    /// Administration command to run.
    #[command(subcommand)]
    command: Commands,
}

/// Top-level command groups.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Node lifecycle: start, stop, restart, status, upgrade.
    Node {
        /// Node subcommand.
        #[command(subcommand)]
        cmd: NodeCommand,
    },
    /// Validator operations: register, stake, monitor, report.
    Validator {
        /// Validator subcommand.
        #[command(subcommand)]
        cmd: ValidatorCommand,
    },
    /// Network administration: subnets, bridges, peers.
    Network {
        /// Network subcommand.
        #[command(subcommand)]
        cmd: NetworkCommand,
    },
    /// Governance: proposals, voting, delegation.
    #[command(alias = "gov")]
    Governance {
        /// Governance subcommand.
        #[command(subcommand)]
        cmd: GovernanceCommand,
    },
    /// TEE management: detect platforms, verify attestation, configure.
    Tee {
        /// TEE subcommand.
        #[command(subcommand)]
        cmd: TeeCommand,
    },
    /// Key management: generate, import, export, backup.
    Keys {
        /// Keys subcommand.
        #[command(subcommand)]
        cmd: KeysCommand,
    },
    /// Configuration management: view, set, validate, export.
    Config {
        /// Config subcommand.
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// Node and network status queries.
    Status {
        /// Status subcommand.
        #[command(subcommand)]
        cmd: StatusCommand,
    },
}

// ============================================================
// ENTRY POINT
// ============================================================

fn main() {
    let cli = Cli::parse();

    // Initialize logging based on verbosity flags.
    let log_level = if cli.verbose {
        "debug"
    } else if cli.quiet {
        "error"
    } else {
        "warn"
    };

    init_logging(log_level);

    // Build CLI context from global arguments.
    let context = match build_context(&cli) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    // Build output writer.
    let output = OutputWriter::new(cli.output.clone(), cli.quiet);

    // Dispatch command.
    let exit_code = match dispatch(&cli.command, context, output) {
        Ok(()) => 0,
        Err(e) => {
            handle_error(&e, cli.output);
            1
        }
    };

    process::exit(exit_code);
}

// ============================================================
// COMMAND DISPATCH
// ============================================================

fn dispatch(
    command: &Commands,
    ctx: CliContext,
    output: OutputWriter,
) -> CliResult<()> {
    // All commands run in a tokio runtime since they need async API calls.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::ConnectionFailed {
            reason: format!("Failed to create async runtime: {e}"),
        })?;

    runtime.block_on(async move {
        match command {
            Commands::Node { cmd } => cmd.run(&ctx, &output),
            Commands::Validator { cmd } => cmd.run(&ctx, &output),
            Commands::Network { cmd } => cmd.run(&ctx, &output),
            Commands::Governance { cmd } => cmd.run(&ctx, &output),
            Commands::Tee { cmd } => cmd.run(&ctx, &output),
            Commands::Keys { cmd } => cmd.run(&ctx, &output),
            Commands::Config { cmd } => cmd.run(&ctx, &output),
            Commands::Status { cmd } => cmd.run(&ctx, &output),
        }
    })
}

// ============================================================
// CONTEXT CONSTRUCTION
// ============================================================

fn build_context(cli: &Cli) -> CliResult<CliContext> {
    let endpoint = cli
        .endpoint
        .clone()
        .unwrap_or_else(|| "http://localhost:8731".to_string());

    let network_ctx = NetworkContext::new(&cli.network, &endpoint)?;

    // Build a GlobalArgs snapshot that command handlers can use to access
    // the top-level options (endpoint, network, no-confirm) without the full Cli.
    let _global_args = GlobalArgs {
        endpoint: cli.endpoint.clone(),
        network: cli.network.clone(),
        no_confirm: cli.no_confirm,
    };

    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(|| {
            let mut p = dirs::home_dir().unwrap_or_default();
            p.push(".aevor");
            p.push("cli.toml");
            p
        });

    CliContext::new(network_ctx, config_path, cli.no_confirm)
}

// ============================================================
// ERROR HANDLING
// ============================================================

fn handle_error(e: &CliError, format: OutputFormat) {
    // Emit a structured tracing error record so log aggregators capture it.
    error!(error = %e, "CLI command failed");

    match format {
        OutputFormat::Json => {
            eprintln!("{{\"error\": \"{e}\"}}");
        }
        _ => {
            eprintln!("Error: {e}");

            // Provide contextual hints for common errors.
            match e {
                CliError::NodeNotRunning => {
                    eprintln!("Hint: Start the node with `aevor node start`");
                }
                CliError::MissingConfig { field } => {
                    eprintln!("Hint: Set {field} in ~/.aevor/cli.toml or pass it as an argument");
                }
                CliError::ConfirmationRequired => {
                    eprintln!("Hint: Add --yes to bypass confirmation");
                }
                CliError::InsufficientPermissions { command } => {
                    eprintln!("Hint: This command ({command}) requires validator-level credentials");
                }
                _ => {}
            }
        }
    }
}

// ============================================================
// LOGGING
// ============================================================

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).compact())
        .init();
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_node_status() {
        let args = vec!["aevor", "status"];
        let cli = Cli::parse_from(args);
        assert!(matches!(cli.command, Commands::Status { .. }));
    }

    #[test]
    fn cli_parses_validator_command() {
        let args = vec!["aevor", "validator", "status"];
        let cli = Cli::parse_from(args);
        assert!(matches!(cli.command, Commands::Validator { .. }));
    }

    #[test]
    fn cli_defaults_to_mainnet() {
        let args = vec!["aevor", "status"];
        let cli = Cli::parse_from(args);
        assert_eq!(cli.network, "mainnet");
    }

    #[test]
    fn cli_default_output_format_is_human() {
        let args = vec!["aevor", "status"];
        let cli = Cli::parse_from(args);
        assert!(matches!(cli.output, OutputFormat::Human));
    }

    #[test]
    fn governance_alias_works() {
        let args = vec!["aevor", "gov", "list"];
        let cli = Cli::parse_from(args);
        assert!(matches!(cli.command, Commands::Governance { .. }));
    }
}
