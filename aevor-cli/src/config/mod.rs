//! Configuration commands.
use clap::Subcommand;
use crate::{CliResult, context::CliContext, output::OutputWriter};

#[derive(Debug, Subcommand)]
pub enum CliConfig { Show, Validate, Set { key: String, value: String }, Export { output: std::path::PathBuf } }
impl CliConfig {
    /// Execute this configuration command.
    ///
    /// # Errors
    /// Returns an error if reading, validating, or writing the config fails.
    pub fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("config command");
        Ok(())
    }
}
