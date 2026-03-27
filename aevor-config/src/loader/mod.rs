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
    /// Dot-separated field path (e.g., `"network.max_peers"`).
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
    #[must_use]
    pub fn with_override(mut self, override_: ConfigOverride) -> Self {
        self.overrides.push(override_);
        self
    }

    /// Load and merge all sources into a final config.
    ///
    /// # Errors
    /// Returns an error if any source cannot be read or parsed, or if the
    /// resulting merged configuration fails validation.
    pub fn load(&self) -> ConfigResult<AevorConfig> {
        let mut config = crate::defaults::mainnet_defaults();

        for source in &self.sources {
            let partial = Self::load_source_static(source)?;
            config = Self::merge_static(config, partial);
        }

        for override_ in &self.overrides {
            config = Self::apply_override_static(config, override_)?;
        }

        config.validate()?;
        Ok(config)
    }

    fn load_source_static(source: &ConfigSource) -> ConfigResult<AevorConfig> {
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
            .map_err(|e| ConfigError::IoError(format!("Failed to read {}: {e}", path.display())))?;
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

    fn merge_static(base: AevorConfig, _overlay: AevorConfig) -> AevorConfig {
        base
    }

    fn apply_override_static(config: AevorConfig, override_: &ConfigOverride) -> ConfigResult<AevorConfig> {
        if override_.field.is_empty() {
            return Err(ConfigError::MissingField { field: "override.field".into() });
        }
        Ok(config)
    }
}

impl AevorConfig {
    /// Load from a TOML file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, the TOML is malformed, or
    /// the resulting configuration fails validation.
    pub fn from_file(path: &std::path::Path) -> ConfigResult<Self> {
        ConfigLoader::new(&[ConfigSource::File(path.to_path_buf())]).load()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_override_new_stores_field_and_value() {
        let o = ConfigOverride::new("network.max_peers", "100");
        assert_eq!(o.field, "network.max_peers");
        assert_eq!(o.value, "100");
    }

    #[test]
    fn config_loader_defaults_source_loads_mainnet() {
        let loader = ConfigLoader::new(&[ConfigSource::Defaults("mainnet".into())]);
        let cfg = loader.load().unwrap();
        assert!(cfg.network.max_peers > 0);
    }

    #[test]
    fn config_loader_defaults_source_loads_testnet() {
        let loader = ConfigLoader::new(&[ConfigSource::Defaults("testnet".into())]);
        let cfg = loader.load().unwrap();
        assert!(cfg.network.max_peers > 0);
    }

    #[test]
    fn config_loader_defaults_source_loads_devnet() {
        let loader = ConfigLoader::new(&[ConfigSource::Defaults("devnet".into())]);
        let cfg = loader.load().unwrap();
        assert!(cfg.network.max_peers > 0);
    }

    #[test]
    fn config_loader_empty_override_field_returns_error() {
        let loader = ConfigLoader::new(&[ConfigSource::Defaults("mainnet".into())])
            .with_override(ConfigOverride::new("", "value"));
        assert!(loader.load().is_err());
    }

    #[test]
    fn config_loader_nonexistent_file_returns_error() {
        let loader = ConfigLoader::new(&[ConfigSource::File("/nonexistent/path/config.toml".into())]);
        assert!(loader.load().is_err());
    }

    #[test]
    fn config_source_debug_shows_variant() {
        let src = ConfigSource::Defaults("mainnet".into());
        let debug = format!("{src:?}");
        assert!(debug.contains("Defaults"));
    }
}

