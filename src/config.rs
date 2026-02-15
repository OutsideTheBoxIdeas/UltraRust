use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::types::UltraRustyConfig;

/// Embedded default clippy configuration
pub const DEFAULT_CLIPPY_CONFIG: &str = include_str!("config/clippy_config.toml");

/// Embedded default deny configuration
pub const DEFAULT_DENY_CONFIG: &str = include_str!("config/deny_config.toml");

/// Load UltraRusty configuration from the target project's Cargo.toml
/// Falls back to defaults if the section is missing.
pub fn load_config(project_path: &Path, config_override: Option<&Path>) -> Result<UltraRustyConfig> {
    // If a config override is specified, try to load from that file
    if let Some(config_path) = config_override {
        let content = fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;
        let parsed: toml::Value = content
            .parse()
            .with_context(|| format!("Failed to parse config file: {}", config_path.display()))?;
        return config_from_toml_value(&parsed);
    }

    // Otherwise, look in the project's Cargo.toml under [package.metadata.ultrarusty]
    let cargo_toml_path = project_path.join("Cargo.toml");
    if cargo_toml_path.exists() {
        let content = fs::read_to_string(&cargo_toml_path)
            .with_context(|| format!("Failed to read {}", cargo_toml_path.display()))?;
        let parsed: toml::Value = content
            .parse()
            .with_context(|| format!("Failed to parse {}", cargo_toml_path.display()))?;

        if let Some(metadata) = parsed
            .get("package")
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("ultrarusty"))
        {
            return config_from_toml_value(metadata);
        }
    }

    // Fall back to defaults
    Ok(UltraRustyConfig::default())
}

/// Parse an UltraRustyConfig from a TOML value
fn config_from_toml_value(value: &toml::Value) -> Result<UltraRustyConfig> {
    let mut config = UltraRustyConfig::default();

    if let Some(v) = value.get("max-complexity").and_then(|v| v.as_integer()) {
        config.max_complexity = v as usize;
    }
    if let Some(v) = value.get("max-function-lines").and_then(|v| v.as_integer()) {
        config.max_function_lines = v as usize;
    }
    if let Some(v) = value.get("max-parameters").and_then(|v| v.as_integer()) {
        config.max_parameters = v as usize;
    }
    if let Some(v) = value.get("max-generic-depth").and_then(|v| v.as_integer()) {
        config.max_generic_depth = v as usize;
    }
    if let Some(v) = value.get("max-nesting").and_then(|v| v.as_integer()) {
        config.max_nesting = v as usize;
    }
    if let Some(v) = value
        .get("geiger-unsafe-threshold")
        .and_then(|v| v.as_integer())
    {
        config.geiger_unsafe_threshold = v as usize;
    }
    if let Some(v) = value
        .get("geiger-transitive-threshold")
        .and_then(|v| v.as_integer())
    {
        config.geiger_transitive_threshold = v as usize;
    }
    if let Some(v) = value.get("security-checks").and_then(|v| v.as_bool()) {
        config.security_checks = v;
    }
    if let Some(v) = value.get("supply-chain-checks").and_then(|v| v.as_bool()) {
        config.supply_chain_checks = v;
    }

    Ok(config)
}

/// Write the embedded clippy config to a temporary location in the project
pub fn write_clippy_config(project_path: &Path) -> Result<PathBuf> {
    let config_path = project_path.join(".ultrarusty-clippy.toml");
    fs::write(&config_path, DEFAULT_CLIPPY_CONFIG)
        .with_context(|| format!("Failed to write clippy config to {}", config_path.display()))?;
    Ok(config_path)
}

/// Write the embedded deny config to a temporary location in the project
pub fn write_deny_config(project_path: &Path) -> Result<PathBuf> {
    let config_path = project_path.join(".ultrarusty-deny.toml");
    fs::write(&config_path, DEFAULT_DENY_CONFIG)
        .with_context(|| format!("Failed to write deny config to {}", config_path.display()))?;
    Ok(config_path)
}

/// Clean up temporary config files
pub fn cleanup_configs(project_path: &Path) {
    let _ = fs::remove_file(project_path.join(".ultrarusty-clippy.toml"));
    let _ = fs::remove_file(project_path.join(".ultrarusty-deny.toml"));
}
