pub mod model;

pub use model::TimmyConfig;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read configuration file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse TOML configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("Failed to serialize configuration to TOML: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// Configuration manager handling load, save, and default paths.
pub struct ConfigManager;

impl ConfigManager {
    /// Resolves the default configuration path for TIMMY.
    pub fn default_config_path() -> PathBuf {
        if let Some(proj_dirs) = directories::ProjectDirs::from("com", "timmy", "timmy") {
            proj_dirs.config_dir().join("config.toml")
        } else {
            PathBuf::from("config.toml")
        }
    }

    /// Loads configuration from a specific path, or falls back to default if file doesn't exist.
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<TimmyConfig, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(TimmyConfig::default());
        }
        let content = fs::read_to_string(path)?;
        let config: TimmyConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Loads configuration from standard location or creates default file if missing.
    pub fn load_or_create_default() -> (TimmyConfig, PathBuf) {
        let path = Self::default_config_path();
        if path.exists() {
            match Self::load_from_path(&path) {
                Ok(cfg) => (cfg, path),
                Err(_) => (TimmyConfig::default(), path),
            }
        } else {
            let default_cfg = TimmyConfig::default();
            // Attempt to write default config
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(toml_str) = toml::to_string_pretty(&default_cfg) {
                let _ = fs::write(&path, toml_str);
            }
            (default_cfg, path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validity() {
        let cfg = TimmyConfig::default();
        let serialized = toml::to_string_pretty(&cfg).expect("Must serialize");
        let parsed: TimmyConfig = toml::from_str(&serialized).expect("Must deserialize");
        assert_eq!(
            cfg.general.refresh_interval_ms,
            parsed.general.refresh_interval_ms
        );
    }
}
