use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export core analysis types from driver module
pub use crate::driver::{Finding, Severity};

/// Result from Stage 1: Supply Chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainResult {
    pub pass: bool,
    pub vulnerabilities: usize,
    pub banned_deps: usize,
    pub unsafe_in_deps: usize,
    pub findings: Vec<Finding>,
}

impl Default for SupplyChainResult {
    fn default() -> Self {
        Self {
            pass: true,
            vulnerabilities: 0,
            banned_deps: 0,
            unsafe_in_deps: 0,
            findings: Vec::new(),
        }
    }
}

/// Result from Stage 2: Compile + Lint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileLintResult {
    pub pass: bool,
    pub violations: Vec<Finding>,
}

impl Default for CompileLintResult {
    fn default() -> Self {
        Self {
            pass: true,
            violations: Vec::new(),
        }
    }
}

/// Result from Stage 3: Security Scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityResult {
    pub pass: bool,
    pub findings: Vec<Finding>,
}

impl Default for SecurityResult {
    fn default() -> Self {
        Self {
            pass: true,
            findings: Vec::new(),
        }
    }
}

/// Aggregated result from all stages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResults {
    pub supply_chain: SupplyChainResult,
    pub compile_lint: CompileLintResult,
    pub security: SecurityResult,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total_issues: usize,
    pub by_severity: SeverityCounts,
}

/// Counts by severity level
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    #[serde(skip_serializing_if = "is_zero")]
    pub critical: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub high: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub medium: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub low: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub deny: usize,
}

fn is_zero(val: &usize) -> bool {
    *val == 0
}

/// The full pipeline report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineReport {
    pub ultrarust_version: String,
    pub pass: bool,
    pub stages: StageResults,
    pub summary: Summary,
}

/// Configuration for UltraRust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltraRustConfig {
    /// Maximum cognitive complexity per function
    pub max_complexity: usize,
    /// Maximum lines per function
    pub max_function_lines: usize,
    /// Maximum function parameters
    pub max_parameters: usize,
    /// Maximum generic type parameters
    pub max_generic_depth: usize,
    /// Maximum nesting depth
    pub max_nesting: usize,
    /// Unsafe code threshold for direct dependencies (cargo-geiger)
    pub geiger_unsafe_threshold: usize,
    /// Unsafe code threshold for transitive dependencies (cargo-geiger)
    pub geiger_transitive_threshold: usize,
    /// Whether to run security checks
    pub security_checks: bool,
    /// Whether to run supply chain checks
    pub supply_chain_checks: bool,
}

impl Default for UltraRustConfig {
    fn default() -> Self {
        Self {
            max_complexity: 12,
            max_function_lines: 80,
            max_parameters: 5,
            max_generic_depth: 4,
            max_nesting: 4,
            geiger_unsafe_threshold: 0,
            geiger_transitive_threshold: 50,
            security_checks: true,
            supply_chain_checks: true,
        }
    }
}

/// Which stage to run (or all)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageFilter {
    All,
    SupplyChain,
    Lint,
    Security,
}

/// CLI options passed through the pipeline
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Path to the target project
    pub project_path: PathBuf,
    /// Optional config file path override
    pub config_path: Option<PathBuf>,
    /// Output JSON to stdout
    pub json_output: bool,
    /// Which stage(s) to run
    pub stage_filter: StageFilter,
    /// Verbose output
    pub verbose: bool,
}
