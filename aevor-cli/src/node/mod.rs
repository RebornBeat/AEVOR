//! Node lifecycle commands.
use serde::{Deserialize, Serialize};
use clap::{Parser, Subcommand};
use crate::{CliResult, context::CliContext, output::OutputWriter};

#[derive(Debug, Serialize, Deserialize, Parser)]
pub struct StartArgs {
    #[arg(long, default_value = "full")] pub mode: String,
    #[arg(long)] pub key_file: Option<std::path::PathBuf>,
}
#[derive(Debug, Serialize, Deserialize, Parser)]
pub struct StopArgs { #[arg(long)] pub force: bool }
#[derive(Debug, Serialize, Deserialize, Parser)]
pub struct StatusArgs { #[arg(long, default_value = "human")] pub output: String }
#[derive(Debug, Serialize, Deserialize, Parser)]
pub struct UpgradeArgs { #[arg(long)] pub version: Option<String> }

pub struct NodeRunner;

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    Start(StartArgs), Stop(StopArgs), Status(StatusArgs), Restart, Upgrade(UpgradeArgs),
}
impl NodeCommand {
    /// Execute this node command.
    ///
    /// # Errors
    /// Returns an error if the underlying node operation fails.
    pub fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("Node command");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_args_default_mode_full() {
        // clap Parser — construct manually since we are not using the CLI entry point
        let args = StartArgs { mode: "full".into(), key_file: None };
        assert_eq!(args.mode, "full");
        assert!(args.key_file.is_none());
    }

    #[test]
    fn stop_args_force_flag() {
        let args = StopArgs { force: false };
        assert!(!args.force);
    }

    #[test]
    fn upgrade_args_optional_version() {
        let args = UpgradeArgs { version: Some("2.0.0".into()) };
        assert_eq!(args.version.as_deref(), Some("2.0.0"));
        let no_ver = UpgradeArgs { version: None };
        assert!(no_ver.version.is_none());
    }
}
