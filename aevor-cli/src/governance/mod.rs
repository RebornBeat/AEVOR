//! Governance commands.
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use crate::{CliResult, context::CliContext, output::OutputWriter};

#[derive(Debug, Args)]
pub struct ProposeArgs { #[arg(long)] pub r#type: String, #[arg(long)] pub description: String }
#[derive(Debug, Args)]
pub struct VoteArgs { #[arg(long)] pub proposal_id: String, #[arg(long)] pub choice: String }
#[derive(Debug, Args)]
pub struct DelegateArgs { #[arg(long)] pub to: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceStatus { pub active_proposals: usize, pub pending_executions: usize }

#[derive(Debug, Subcommand)]
pub enum GovernanceCommand {
    Propose(ProposeArgs), Vote(VoteArgs), Delegate(DelegateArgs), List, Status,
}
impl GovernanceCommand {
    pub async fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("governance command");
        Ok(())
    }
}
