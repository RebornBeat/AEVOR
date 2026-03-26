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
pub struct ValidatorMonitor;

#[derive(Debug, Subcommand)]
pub enum ValidatorCommand {
    Register(RegisterArgs), Stake(StakeArgs), Unstake(UnstakeArgs), Status, List, SlashReport(SlashReportArgs),
}
impl ValidatorCommand {
    pub async fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("validator command");
        Ok(())
    }
}
