use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config;
use crate::types::{Finding, Severity, SupplyChainResult, UltraRustConfig};

/// Run all supply chain checks on the target project
pub fn run(project_path: &Path, config: &UltraRustConfig, verbose: bool) -> Result<SupplyChainResult> {
    let mut result = SupplyChainResult::default();

    if verbose {
        eprintln!("[supply-chain] Running supply chain checks...");
    }

    // Run cargo-audit
    match run_cargo_audit(project_path, verbose) {
        Ok(findings) => {
            result.vulnerabilities = findings.len();
            if !findings.is_empty() {
                result.pass = false;
            }
            result.findings.extend(findings);
        }
        Err(e) => {
            if verbose {
                eprintln!("[supply-chain] cargo-audit: {}", e);
            }
            result.findings.push(tool_not_found_finding("cargo-audit", &e));
        }
    }

    // Run cargo-deny
    let deny_config_path = config::write_deny_config(project_path)?;
    match run_cargo_deny(project_path, &deny_config_path, verbose) {
        Ok(findings) => {
            result.banned_deps = findings.len();
            if !findings.is_empty() {
                result.pass = false;
            }
            result.findings.extend(findings);
        }
        Err(e) => {
            if verbose {
                eprintln!("[supply-chain] cargo-deny: {}", e);
            }
            result.findings.push(tool_not_found_finding("cargo-deny", &e));
        }
    }

    // Run cargo-geiger
    match run_cargo_geiger(project_path, config, verbose) {
        Ok(findings) => {
            result.unsafe_in_deps = findings.len();
            if !findings.is_empty() {
                result.pass = false;
            }
            result.findings.extend(findings);
        }
        Err(e) => {
            if verbose {
                eprintln!("[supply-chain] cargo-geiger: {}", e);
            }
            result.findings.push(tool_not_found_finding("cargo-geiger", &e));
        }
    }

    // Cleanup temp config files
    config::cleanup_configs(project_path);

    Ok(result)
}

/// Run cargo-audit and parse output
fn run_cargo_audit(project_path: &Path, verbose: bool) -> Result<Vec<Finding>> {
    // Check if cargo-audit is installed
    if which::which("cargo-audit").is_err() {
        anyhow::bail!("cargo-audit is not installed. Install with: cargo install cargo-audit");
    }

    if verbose {
        eprintln!("[supply-chain] Running cargo audit --json ...");
    }

    let output = Command::new("cargo")
        .arg("audit")
        .arg("--json")
        .current_dir(project_path)
        .output()
        .context("Failed to execute cargo audit")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_audit_json(&stdout)
}

/// Parse cargo-audit JSON output into findings
fn parse_audit_json(json_str: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if json_str.trim().is_empty() {
        return Ok(findings);
    }

    let value: serde_json::Value =
        serde_json::from_str(json_str).context("Failed to parse cargo-audit JSON output")?;

    if let Some(vulnerabilities) = value.get("vulnerabilities").and_then(|v| v.get("list")) {
        if let Some(vuln_list) = vulnerabilities.as_array() {
            for vuln in vuln_list {
                let advisory = vuln.get("advisory");
                let id = advisory
                    .and_then(|a| a.get("id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");
                let title = advisory
                    .and_then(|a| a.get("title"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown vulnerability");
                let package_name = vuln
                    .get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let package_version = vuln
                    .get("package")
                    .and_then(|p| p.get("version"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?.?.?");

                findings.push(Finding {
                    source: "cargo-audit".to_owned(),
                    check_name: id.to_owned(),
                    severity: Severity::Critical,
                    file: PathBuf::from("Cargo.lock"),
                    line: 0,
                    col: 0,
                    message: format!(
                        "{}: {} ({}@{})",
                        id, title, package_name, package_version
                    ),
                    snippet: format!("{} = \"{}\"", package_name, package_version),
                    fix: format!("Update {} to a patched version", package_name),
                });
            }
        }
    }

    Ok(findings)
}

/// Run cargo-deny and parse output
fn run_cargo_deny(
    project_path: &Path,
    deny_config_path: &Path,
    verbose: bool,
) -> Result<Vec<Finding>> {
    if which::which("cargo-deny").is_err() {
        anyhow::bail!("cargo-deny is not installed. Install with: cargo install cargo-deny");
    }

    if verbose {
        eprintln!("[supply-chain] Running cargo deny check ...");
    }

    let output = Command::new("cargo")
        .arg("deny")
        .arg("--config")
        .arg(deny_config_path)
        .arg("check")
        .arg("--format")
        .arg("json")
        .current_dir(project_path)
        .output()
        .context("Failed to execute cargo deny")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // cargo-deny outputs JSON lines to stdout, diagnostics to stderr
    let combined = if stdout.trim().is_empty() {
        stderr.to_string()
    } else {
        stdout.to_string()
    };

    parse_deny_output(&combined)
}

/// Parse cargo-deny output (JSON lines format) into findings
fn parse_deny_output(output: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let msg_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");

            if msg_type == "diagnostic" {
                let severity_str = value
                    .get("fields")
                    .and_then(|f| f.get("severity"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("warning");

                if severity_str == "error" || severity_str == "warning" {
                    let message = value
                        .get("fields")
                        .and_then(|f| f.get("message"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown deny violation");

                    let code = value
                        .get("fields")
                        .and_then(|f| f.get("code"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("deny-check");

                    findings.push(Finding {
                        source: "cargo-deny".to_owned(),
                        check_name: code.to_owned(),
                        severity: Severity::High,
                        file: PathBuf::from("Cargo.toml"),
                        line: 0,
                        col: 0,
                        message: message.to_owned(),
                        snippet: String::new(),
                        fix: "Review and fix the dependency issue".to_owned(),
                    });
                }
            }
        }
    }

    Ok(findings)
}

/// Run cargo-geiger and parse output
fn run_cargo_geiger(
    project_path: &Path,
    _config: &UltraRustConfig,
    verbose: bool,
) -> Result<Vec<Finding>> {
    if which::which("cargo-geiger").is_err() {
        anyhow::bail!(
            "cargo-geiger is not installed. Install with: cargo install cargo-geiger"
        );
    }

    if verbose {
        eprintln!("[supply-chain] Running cargo geiger --output-format json ...");
    }

    let output = Command::new("cargo")
        .arg("geiger")
        .arg("--output-format")
        .arg("json")
        .current_dir(project_path)
        .output()
        .context("Failed to execute cargo geiger")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_geiger_json(&stdout, _config)
}

/// Parse cargo-geiger JSON output into findings
fn parse_geiger_json(json_str: &str, config: &UltraRustConfig) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if json_str.trim().is_empty() {
        return Ok(findings);
    }

    let value: serde_json::Value =
        serde_json::from_str(json_str).context("Failed to parse cargo-geiger JSON output")?;

    if let Some(packages) = value.get("packages").and_then(|v| v.as_array()) {
        for package in packages {
            let name = package
                .get("id")
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let is_direct = package
                .get("id")
                .and_then(|v| v.get("is_direct_dep"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let unsafe_count = package
                .get("unsafety")
                .and_then(|u| u.get("used"))
                .and_then(|u| u.get("unsafe_count"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let threshold = if is_direct {
                config.geiger_unsafe_threshold as u64
            } else {
                config.geiger_transitive_threshold as u64
            };

            if unsafe_count > threshold {
                let dep_type = if is_direct {
                    "direct"
                } else {
                    "transitive"
                };
                findings.push(Finding {
                    source: "cargo-geiger".to_owned(),
                    check_name: "unsafe-in-dependency".to_owned(),
                    severity: if is_direct {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    file: PathBuf::from("Cargo.toml"),
                    line: 0,
                    col: 0,
                    message: format!(
                        "{} dependency '{}' has {} unsafe usage(s) (threshold: {})",
                        dep_type, name, unsafe_count, threshold
                    ),
                    snippet: String::new(),
                    fix: format!(
                        "Consider replacing '{}' with a safer alternative",
                        name
                    ),
                });
            }
        }
    }

    Ok(findings)
}

/// Create a finding for when a supply chain tool is not installed
fn tool_not_found_finding(tool: &str, error: &anyhow::Error) -> Finding {
    Finding {
        source: tool.to_owned(),
        check_name: "tool-not-installed".to_owned(),
        severity: Severity::Medium,
        file: PathBuf::new(),
        line: 0,
        col: 0,
        message: format!("{}: {}", tool, error),
        snippet: String::new(),
        fix: format!("Install with: cargo install {}", tool),
    }
}
