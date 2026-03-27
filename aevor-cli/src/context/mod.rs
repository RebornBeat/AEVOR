//! CLI context: shared state across commands.
use crate::CliResult;

#[derive(Clone)]
pub struct NetworkContext { pub network: String, pub endpoint: String }
impl NetworkContext {
    /// Create a new network context.
    ///
    /// # Errors
    /// Currently always succeeds; the `Result` type allows future validation
    /// of the network name and endpoint URL format.
    pub fn new(network: &str, endpoint: &str) -> CliResult<Self> {
        Ok(Self { network: network.to_string(), endpoint: endpoint.to_string() })
    }
}

pub struct AuthContext { pub api_key: Option<String> }

pub struct CliContext {
    pub network: NetworkContext,
    pub config_path: std::path::PathBuf,
    pub no_confirm: bool,
}
impl CliContext {
    /// Create a new CLI context.
    ///
    /// # Errors
    /// Currently always succeeds; the `Result` type allows future validation
    /// of the config path and network settings.
    pub fn new(network: NetworkContext, config_path: std::path::PathBuf, no_confirm: bool) -> CliResult<Self> {
        Ok(Self { network, config_path, no_confirm })
    }
}
