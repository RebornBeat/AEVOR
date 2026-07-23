//! Key management commands — real key custody backed by `aevor-wallet`.
//!
//! Every command here performs actual work: `generate` creates a keypair from OS
//! entropy and writes an encrypted keystore, `import` recovers one from a seed,
//! `export` reveals the public identity (never the secret), and `list` inspects a
//! keystore directory. Passphrases are read from the environment rather than
//! command-line arguments, because arguments are visible in the process table.

use aevor_wallet::{Keystore, Wallet};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::{context::CliContext, output::OutputWriter, CliError, CliResult};

/// Environment variable carrying the keystore passphrase.
const PASSPHRASE_ENV: &str = "AEVOR_KEYSTORE_PASSPHRASE";

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Signature algorithm (currently `ed25519`).
    #[arg(long, default_value = "ed25519")]
    pub algorithm: String,
    /// Where to write the encrypted keystore. Named `--keystore-out` because
    /// `--output` is a global flag selecting the output *format*.
    #[arg(long = "keystore-out")]
    pub keystore_out: std::path::PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// A 32-byte seed, hex-encoded, to recover an existing identity.
    #[arg(long)]
    pub seed: String,
    /// Where to write the encrypted keystore. Named `--keystore-out` because
    /// `--output` is a global flag selecting the output *format*.
    #[arg(long = "keystore-out")]
    pub keystore_out: std::path::PathBuf,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// The keystore to read.
    #[arg(long)]
    pub keystore: std::path::PathBuf,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Directory to scan for keystore files.
    #[arg(long, default_value = ".")]
    pub directory: std::path::PathBuf,
}

/// The public identity of a key — never its secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyInfo {
    pub algorithm: String,
    pub public_key: String,
    pub address: String,
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Generate a new keypair and write an encrypted keystore.
    Generate(GenerateArgs),
    /// Recover an identity from a seed and write an encrypted keystore.
    Import(ImportArgs),
    /// Show the public identity held in a keystore.
    Export(ExportArgs),
    /// List keystores in a directory.
    List(ListArgs),
}

fn passphrase() -> CliResult<String> {
    std::env::var(PASSPHRASE_ENV).map_err(|_| CliError::MissingConfig {
        field: format!(
            "{PASSPHRASE_ENV} (passing a passphrase as an argument would expose it in the \
             process list)"
        ),
    })
}

fn info(wallet: &Wallet) -> KeyInfo {
    KeyInfo {
        algorithm: "ed25519".to_string(),
        public_key: hex::encode(wallet.public_key_bytes()),
        address: hex::encode(wallet.address().0),
    }
}

impl KeysCommand {
    /// Execute this key management command.
    ///
    /// # Errors
    /// Returns an error if the passphrase is unset, the algorithm is unsupported,
    /// the seed is malformed, or the keystore cannot be written or read.
    pub fn run(&self, _ctx: &CliContext, output: &OutputWriter) -> CliResult<()> {
        match self {
            Self::Generate(args) => {
                if args.algorithm != "ed25519" {
                    return Err(CliError::InvalidArgument {
                        arg: "--algorithm".to_string(),
                        reason: format!("'{}' unsupported (supported: ed25519)", args.algorithm),
                    });
                }
                let pass = passphrase()?;
                let wallet = Wallet::generate()
                    .map_err(|e| CliError::IoError(e.to_string()))?;
                Keystore::save(&wallet, &pass, &args.keystore_out)
                    .map_err(|e| CliError::IoError(e.to_string()))?;
                output.print(&info(&wallet));
                Ok(())
            }
            Self::Import(args) => {
                let pass = passphrase()?;
                let raw = hex::decode(args.seed.trim_start_matches("0x"))
                    .map_err(|e| CliError::InvalidArgument {
                        arg: "--seed".to_string(),
                        reason: format!("not hex: {e}"),
                    })?;
                let seed: [u8; 32] = raw.try_into().map_err(|_| CliError::InvalidArgument {
                    arg: "--seed".to_string(),
                    reason: "must be exactly 32 bytes".to_string(),
                })?;
                let wallet = Wallet::from_seed(seed);
                Keystore::save(&wallet, &pass, &args.keystore_out)
                    .map_err(|e| CliError::IoError(e.to_string()))?;
                output.print(&info(&wallet));
                Ok(())
            }
            Self::Export(args) => {
                let pass = passphrase()?;
                let wallet = Keystore::load(&pass, &args.keystore)
                    .map_err(|e| CliError::IoError(e.to_string()))?;
                output.print(&info(&wallet));
                Ok(())
            }
            Self::List(args) => {
                let mut found: Vec<String> = Vec::new();
                let entries = std::fs::read_dir(&args.directory)
                    .map_err(|e| CliError::IoError(e.to_string()))?;
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("json") {
                        // Identify keystores by their format, without needing the
                        // passphrase: the address is public.
                        if let Ok(text) = std::fs::read_to_string(&path) {
                            if text.contains("argon2id") {
                                found.push(path.display().to_string());
                            }
                        }
                    }
                }
                output.print(&found);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_info_carries_the_public_identity_only() {
        let w = Wallet::from_seed([2u8; 32]);
        let i = info(&w);
        assert_eq!(i.algorithm, "ed25519");
        assert_eq!(i.address, hex::encode(w.address().0));
        assert_eq!(i.public_key, hex::encode(w.public_key_bytes()));
        // Nothing secret is present.
        assert!(!i.public_key.is_empty() && !i.address.is_empty());
    }

    #[test]
    fn passphrase_is_required_from_the_environment() {
        std::env::remove_var(PASSPHRASE_ENV);
        assert!(passphrase().is_err(), "an unset passphrase must be an explicit error");
    }
}
