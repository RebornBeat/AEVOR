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
    /// Execute this governance command.
    ///
    /// # Errors
    /// Returns an error if the underlying governance operation fails.
    pub fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("governance command");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_status_stores_counts() {
        let s = GovernanceStatus { active_proposals: 3, pending_executions: 1 };
        assert_eq!(s.active_proposals, 3);
        assert_eq!(s.pending_executions, 1);
    }
}
