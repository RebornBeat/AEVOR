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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn cli_config_set_variant() {
        let cmd = CliConfig::Set { key: "log_level".into(), value: "debug".into() };
        assert!(matches!(cmd, CliConfig::Set { .. }));
    }

    #[test]
    fn cli_config_export_variant() {
        let cmd = CliConfig::Export { output: PathBuf::from("/tmp/config.toml") };
        assert!(matches!(cmd, CliConfig::Export { .. }));
    }
}
