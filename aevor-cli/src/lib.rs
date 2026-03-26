//! # AEVOR CLI: Infrastructure Administration
//!
//! `aevor-cli` provides command-line administration interfaces for managing AEVOR
//! infrastructure — node operations, validator management, network configuration,
//! and governance participation.
//!
//! ## Architectural Boundary
//!
//! This crate provides **infrastructure administration** tools:
//! - Node lifecycle (start, stop, status, upgrade)
//! - Validator operations (register, stake, monitor, slash reporting)
//! - Network administration (subnet creation, bridge management)
//! - Governance participation (proposal submission, voting)
//! - TEE management (attestation verification, platform configuration)
//!
//! It does **not** provide:
//! - Comprehensive development tooling (contract deployment workflows, test runners)
//! - IDE or editor integration
//! - Application-layer management (smart contract ABI generation, SDK scaffolding)
//! - Organizational management features
//!
//! Those capabilities belong in external ecosystem tools that use `aevor-client`
//! to communicate with infrastructure.
//!
//! ## Command Structure
//!
//! ```text
//! aevor
//! ├── node          Node lifecycle management
//! ├── validator     Validator registration and operations
//! ├── network       Network and subnet administration
//! ├── governance    Governance proposal and voting
//! ├── tee           TEE platform management and attestation
//! ├── keys          Key generation and management
//! ├── config        Configuration management
//! └── status        Node and network status queries
//! ```

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ============================================================
// MODULE DECLARATIONS
// ============================================================

/// Node commands: start, stop, restart, status, upgrade.
pub mod node;

/// Validator commands: register, deregister, stake, unstake, monitor.
pub mod validator;

/// Network commands: subnet creation, bridge management, peer management.
pub mod network;

/// Governance commands: proposal submission, voting, delegation.
pub mod governance;

/// TEE commands: platform detection, attestation verification, configuration.
pub mod tee;

/// Key commands: key generation, import, export, backup.
pub mod keys;

/// Config commands: view, set, validate, export configuration.
pub mod config;

/// Status commands: node status, network status, validator status.
pub mod status;

/// Output formatting: JSON, table, and human-readable output modes.
pub mod output;

/// CLI context: shared state across command invocations.
pub mod context;

/// Argument parsing: clap-based argument definitions for all commands.
pub mod args;

// ============================================================
// PRELUDE
// ============================================================

/// CLI prelude — all essential CLI types.
///
/// ```rust
/// use aevor_cli::prelude::*;
/// ```
pub mod prelude {
    pub use crate::node::{
        NodeCommand, StartArgs, StopArgs, StatusArgs, UpgradeArgs,
        NodeRunner,
    };
    pub use crate::validator::{
        ValidatorCommand, RegisterArgs, StakeArgs, UnstakeArgs,
        ValidatorMonitor, SlashReportArgs,
    };
    pub use crate::network::{
        NetworkCommand, SubnetCreateArgs, BridgeArgs, PeerArgs,
        NetworkAdminConfig,
    };
    pub use crate::governance::{
        GovernanceCommand, ProposeArgs, VoteArgs, DelegateArgs,
        GovernanceStatus,
    };
    pub use crate::tee::{
        TeeCommand, DetectArgs, AttestArgs, ConfigureArgs,
        TeeStatusDisplay,
    };
    pub use crate::keys::{
        KeysCommand, GenerateArgs, ImportArgs, ExportArgs,
        KeyInfo,
    };
    pub use crate::output::{
        OutputFormat, TableFormatter, JsonFormatter, HumanFormatter,
        OutputWriter,
    };
    pub use crate::context::{
        CliContext, NetworkContext, AuthContext,
    };
    pub use crate::{CliError, CliResult};
}

// ============================================================
// ERROR TYPES
// ============================================================

/// Errors from CLI operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum CliError {
    /// Invalid argument provided to a command.
    #[error("invalid argument '{arg}': {reason}")]
    InvalidArgument {
        /// Argument name.
        arg: String,
        /// Reason it is invalid.
        reason: String,
    },

    /// Required configuration is missing.
    #[error("missing configuration: {field}")]
    MissingConfig {
        /// Configuration field name.
        field: String,
    },

    /// Infrastructure connection failed.
    #[error("connection failed: {reason}")]
    ConnectionFailed {
        /// Reason for failure.
        reason: String,
    },

    /// Command requires elevated permissions not currently held.
    #[error("insufficient permissions for command: {command}")]
    InsufficientPermissions {
        /// Command that requires elevated permissions.
        command: String,
    },

    /// File IO error during configuration or key operations.
    #[error("IO error: {0}")]
    IoError(String),

    /// Node is not running but command requires a running node.
    #[error("node is not running")]
    NodeNotRunning,

    /// Confirmation required but not provided.
    #[error("confirmation required (use --yes to bypass)")]
    ConfirmationRequired,
}

/// Convenience alias for CLI results.
pub type CliResult<T> = Result<T, CliError>;

// ============================================================
// CONSTANTS
// ============================================================

/// Default node socket path for local IPC.
pub const DEFAULT_NODE_SOCKET: &str = "/var/run/aevor/node.sock";

/// Default configuration directory.
pub const DEFAULT_CONFIG_DIR: &str = "~/.aevor";

/// Default key storage directory.
pub const DEFAULT_KEY_DIR: &str = "~/.aevor/keys";

/// Default log directory.
pub const DEFAULT_LOG_DIR: &str = "~/.aevor/logs";

/// CLI binary name.
pub const CLI_NAME: &str = "aevor";

/// CLI version string.
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_are_nonempty() {
        assert!(!DEFAULT_NODE_SOCKET.is_empty());
        assert!(!DEFAULT_CONFIG_DIR.is_empty());
        assert!(!DEFAULT_KEY_DIR.is_empty());
    }

    #[test]
    fn cli_name_is_correct() {
        assert_eq!(CLI_NAME, "aevor");
    }
}
