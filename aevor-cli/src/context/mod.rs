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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn network_context_stores_network_and_endpoint() {
        let nc = NetworkContext::new("testnet", "https://rpc.testnet.aevor.io").unwrap();
        assert_eq!(nc.network, "testnet");
        assert_eq!(nc.endpoint, "https://rpc.testnet.aevor.io");
    }

    #[test]
    fn cli_context_no_confirm_flag() {
        let nc = NetworkContext::new("devnet", "http://localhost:8080").unwrap();
        let ctx = CliContext::new(nc, PathBuf::from("/tmp/.aevor"), true).unwrap();
        assert!(ctx.no_confirm);
    }

    #[test]
    fn auth_context_optional_api_key() {
        let auth = AuthContext { api_key: Some("sk-test-abc".into()) };
        assert!(auth.api_key.is_some());
        let no_key = AuthContext { api_key: None };
        assert!(no_key.api_key.is_none());
    }
}
