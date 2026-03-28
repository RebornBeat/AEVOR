//! Key management commands.
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use crate::{CliResult, context::CliContext, output::OutputWriter};

#[derive(Debug, Args)]
pub struct GenerateArgs { #[arg(long, default_value = "ed25519")] pub algorithm: String }
#[derive(Debug, Args)]
pub struct ImportArgs { #[arg(long)] pub file: std::path::PathBuf }
#[derive(Debug, Args)]
pub struct ExportArgs { #[arg(long)] pub output: std::path::PathBuf, #[arg(long)] pub format: Option<String> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyInfo { pub algorithm: String, pub public_key: String, pub address: String }

#[derive(Debug, Subcommand)]
pub enum KeysCommand { Generate(GenerateArgs), Import(ImportArgs), Export(ExportArgs), List }
impl KeysCommand {
    /// Execute this key management command.
    ///
    /// # Errors
    /// Returns an error if key generation, import, or export fails.
    pub fn run(&self, _ctx: &CliContext, _output: &OutputWriter) -> CliResult<()> {
        println!("keys command");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_info_stores_algorithm_and_address() {
        let k = KeyInfo { algorithm: "ed25519".into(), public_key: "0xABCD".into(), address: "0x1234".into() };
        assert_eq!(k.algorithm, "ed25519");
        assert!(!k.address.is_empty());
    }
}
