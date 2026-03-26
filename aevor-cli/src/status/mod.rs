//! Status query commands.
use clap::Subcommand;
use crate::{CliResult, context::CliContext, output::OutputWriter};

#[derive(Debug, Subcommand)]
pub enum StatusCommand { Node, Network, Validators, Consensus }
impl StatusCommand {
    pub async fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("status command");
        Ok(())
    }
}
