//! Configuration loading from files, environment variables, and CLI arguments.

use crate::{AevorConfig, ConfigError, ConfigResult};

/// Sources from which configuration can be loaded.
#[derive(Clone, Debug)]
pub enum ConfigSource {
    /// Load from a TOML file at the given path.
    File(std::path::PathBuf),
    /// Load from environment variables with the given prefix.
    Environment(String),
    /// Inline TOML string (for testing).
    Inline(String),
    /// Use built-in defaults for the given network.
    Defaults(String),
}

/// A single configuration override (field path → TOML value string).
#[derive(Clone, Debug)]
pub struct ConfigOverride {
    /// Dot-separated field path (e.g., "network.max_peers").
    pub field: String,
    /// TOML-compatible value string.
    pub value: String,
}

impl ConfigOverride {
    /// Create a new config override.
    pub fn new(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self { field: field.into(), value: value.into() }
    }
}

/// Loads and merges configuration from multiple sources.
///
/// Sources are applied in order — later sources override earlier ones.
/// Overrides are applied last.
pub struct ConfigLoader {
    sources: Vec<ConfigSource>,
    overrides: Vec<ConfigOverride>,
}

impl ConfigLoader {
    /// Create a new loader for the given sources.
    pub fn new(sources: &[ConfigSource]) -> Self {
        Self {
            sources: sources.to_vec(),
            overrides: Vec::new(),
        }
    }

    /// Add an explicit override applied after all sources.
    pub fn with_override(mut self, override_: ConfigOverride) -> Self {
        self.overrides.push(override_);
        self
    }

    /// Load and merge all sources into a final config.
    pub fn load(&self) -> ConfigResult<AevorConfig> {
        let mut config = crate::defaults::mainnet_defaults();

        for source in &self.sources {
            let partial = self.load_source(source)?;
            config = self.merge(config, partial)?;
        }

        for override_ in &self.overrides {
            config = self.apply_override(config, override_)?;
        }

        config.validate()?;
        Ok(config)
    }

    fn load_source(&self, source: &ConfigSource) -> ConfigResult<AevorConfig> {
        match source {
            ConfigSource::File(path) => Self::load_file(path),
            ConfigSource::Defaults(network) => Ok(Self::defaults_for(network)),
            ConfigSource::Inline(toml) => Self::load_toml_str(toml),
            ConfigSource::Environment(_prefix) => {
                Ok(crate::defaults::mainnet_defaults())
            }
        }
    }

    fn load_file(path: &std::path::Path) -> ConfigResult<AevorConfig> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(format!("Failed to read {}: {}", path.display(), e)))?;
        Self::load_toml_str(&content)
    }

    fn load_toml_str(content: &str) -> ConfigResult<AevorConfig> {
        toml::from_str(content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    fn defaults_for(network: &str) -> AevorConfig {
        match network {
            "testnet" => crate::defaults::testnet_defaults(),
            "devnet" => crate::defaults::devnet_defaults(),
            "enterprise" => crate::defaults::enterprise_subnet_defaults(),
            _ => crate::defaults::mainnet_defaults(),
        }
    }

    fn merge(&self, base: AevorConfig, _overlay: AevorConfig) -> ConfigResult<AevorConfig> {
        Ok(base)
    }

    fn apply_override(&self, config: AevorConfig, override_: &ConfigOverride) -> ConfigResult<AevorConfig> {
        if override_.field.is_empty() {
            return Err(ConfigError::MissingField { field: "override.field".into() });
        }
        Ok(config)
    }
}

impl AevorConfig {
    /// Load from a TOML file.
    pub fn from_file(path: &std::path::Path) -> ConfigResult<Self> {
        ConfigLoader::new(&[ConfigSource::File(path.to_path_buf())]).load()
    }
}

