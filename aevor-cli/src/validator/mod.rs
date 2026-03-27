//! Validator management commands.
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use crate::{CliResult, context::CliContext, output::OutputWriter};

#[derive(Debug, Args)]
pub struct RegisterArgs { #[arg(long)] pub stake: u128, #[arg(long)] pub key_file: Option<std::path::PathBuf> }
#[derive(Debug, Args)]
pub struct StakeArgs { #[arg(long)] pub amount: u128, #[arg(long)] pub validator: String }
#[derive(Debug, Args)]
pub struct UnstakeArgs { #[arg(long)] pub amount: u128, #[arg(long)] pub validator: String }
#[derive(Debug, Args)]
pub struct SlashReportArgs { #[arg(long)] pub validator: String, #[arg(long)] pub evidence: String }
/// Runtime monitoring state for a validator.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ValidatorMonitor {
    /// Consecutive rounds with attestation.
    pub consecutive_attestations: u64,
    /// Whether the validator is currently jailed.
    pub is_jailed: bool,
}

#[derive(Debug, Subcommand)]
pub enum ValidatorCommand {
    Register(RegisterArgs), Stake(StakeArgs), Unstake(UnstakeArgs), Status, List, SlashReport(SlashReportArgs),
}
impl ValidatorCommand {
    /// Execute this validator command.
    ///
    /// # Errors
    /// Returns an error if the underlying validator operation fails.
    pub fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("validator command");
        Ok(())
    }
}
