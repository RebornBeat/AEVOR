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
    pub async fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("Node command");
        Ok(())
    }
}
