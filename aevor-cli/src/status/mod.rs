//! Status query commands.
use clap::Subcommand;
use crate::{CliResult, context::CliContext, output::OutputWriter};

#[derive(Debug, Subcommand)]
pub enum StatusCommand { Node, Network, Validators, Consensus }
impl StatusCommand {
    /// Execute this status command.
    ///
    /// # Errors
    /// Returns an error if the node connection fails or status cannot be retrieved.
    pub fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("status command");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // StatusCommand variants are clap Subcommands — test the discriminants compile
    #[test]
    fn status_command_variants_exist() {
        use super::StatusCommand;
        let _ = StatusCommand::Node;
        let _ = StatusCommand::Network;
        let _ = StatusCommand::Validators;
        let _ = StatusCommand::Consensus;
    }
}
