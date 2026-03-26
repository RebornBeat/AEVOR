//! Network management commands.
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use crate::{CliResult, context::CliContext, output::OutputWriter};

#[derive(Debug, Args)]
pub struct SubnetCreateArgs { #[arg(long)] pub name: String, #[arg(long)] pub permissioned: bool }
#[derive(Debug, Args)]
pub struct BridgeArgs { #[arg(long)] pub target: String }
#[derive(Debug, Args)]
pub struct PeerArgs { #[arg(long)] pub address: Option<String> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkAdminConfig { pub max_peers: usize, pub bootstrap: Vec<String> }

#[derive(Debug, Subcommand)]
pub enum NetworkCommand { SubnetCreate(SubnetCreateArgs), Bridge(BridgeArgs), Peers(PeerArgs), Status }
impl NetworkCommand {
    pub async fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("network command");
        Ok(())
    }
}
