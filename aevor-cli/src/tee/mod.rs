//! TEE commands.
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use crate::{CliResult, context::CliContext, output::OutputWriter};

#[derive(Debug, Args)]
pub struct DetectArgs;
#[derive(Debug, Args)]
pub struct AttestArgs { #[arg(long)] pub platform: Option<String> }
#[derive(Debug, Args)]
pub struct ConfigureArgs { #[arg(long)] pub platform: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeStatusDisplay { pub platform: String, pub available: bool, pub is_production: bool }

#[derive(Debug, Subcommand)]
pub enum TeeCommand { Detect(DetectArgs), Attest(AttestArgs), Configure(ConfigureArgs), Status }
impl TeeCommand {
    /// Execute this TEE command.
    ///
    /// # Errors
    /// Returns an error if the underlying TEE operation fails.
    pub fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("tee command");
        Ok(())
    }
}
