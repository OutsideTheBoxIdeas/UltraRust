// Analysis driver - syn-based source analysis engine
// Defines core types (Finding, Severity, AnalysisPass) and the AnalysisDriver
// that walks all .rs files, parses them with syn, and runs all registered passes.

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::lints;
use crate::security;

/// Severity levels for findings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Info => write!(f, "info"),
        }
    }
}

/// A single finding produced by an analysis pass.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Origin category: "ultrarusty" for custom lints, "security" for security checks.
    pub source: String,
    /// Name of the check that produced this finding.
    pub check_name: String,
    /// Severity of the finding.
    pub severity: Severity,
    /// File path where the finding was detected.
    pub file: PathBuf,
    /// Line number (1-based).
    pub line: usize,
    /// Column number (0-based).
    pub col: usize,
    /// Human-readable description.
    pub message: String,
    /// Source code snippet around the finding.
    pub snippet: String,
    /// Suggested fix.
    pub fix: String,
}

/// Trait that all custom lint and security checks implement.
pub trait AnalysisPass: Send + Sync {
    /// Returns the name of this analysis pass (e.g. "no_interior_mutability").
    fn name(&self) -> &str;

    /// Runs this pass against a parsed file and returns any findings.
    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding>;
}

/// The analysis driver holds all registered passes and orchestrates analysis.
pub struct AnalysisDriver {
    passes: Vec<Box<dyn AnalysisPass>>,
}

impl AnalysisDriver {
    /// Creates a new driver with all built-in passes registered.
    pub fn new() -> Self {
        let mut driver = AnalysisDriver { passes: Vec::new() };
        driver.register_all();
        driver
    }

    /// Registers all 5 custom lints and 10 security checks.
    fn register_all(&mut self) {
        // Custom lints (5)
        self.passes.push(Box::new(lints::no_interior_mut::NoInteriorMutability));
        self.passes.push(Box::new(lints::no_string_errors::NoStringErrors));
        self.passes.push(Box::new(lints::no_infinite_loops::NoInfiniteLoops));
        self.passes.push(Box::new(lints::public_api_lifetimes::PublicApiLifetimes));
        self.passes.push(Box::new(lints::bounded_generics::BoundedGenerics));

        // Security checks (10)
        self.passes.push(Box::new(security::hardcoded_secrets::HardcodedSecrets::new()));
        self.passes.push(Box::new(security::command_injection::CommandInjection));
        self.passes.push(Box::new(security::path_traversal::PathTraversal));
        self.passes.push(Box::new(security::weak_crypto::WeakCrypto));
        self.passes.push(Box::new(security::insecure_deser::InsecureDeserialization));
        self.passes.push(Box::new(security::sql_injection::SqlInjection));
        self.passes.push(Box::new(security::unbounded_reads::UnboundedReads));
        self.passes.push(Box::new(security::insecure_tls::InsecureTls));
        self.passes.push(Box::new(security::insecure_random::InsecureRandom));
        self.passes.push(Box::new(security::timing_attack::TimingAttack));
    }

    /// Analyzes all .rs files under the given project path.
    /// Returns all findings from all passes.
    pub fn analyze_project(&self, project_path: &Path) -> Vec<Finding> {
        let mut all_findings = Vec::new();

        for entry in WalkDir::new(project_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path().extension().map_or(false, |ext| ext == "rs")
                    && !is_excluded_path(e.path())
            })
        {
            let path = entry.path();
            let source = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let parsed = match syn::parse_file(&source) {
                Ok(f) => f,
                Err(_) => continue, // skip files that don't parse
            };

            for pass in &self.passes {
                let findings = pass.check_file(&parsed, path);
                all_findings.extend(findings);
            }
        }

        all_findings
    }

    /// Returns the number of registered passes.
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }
}

/// Returns true if the path should be excluded from analysis
/// (e.g. build artifacts, test fixtures, generated code).
fn is_excluded_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains("/target/")
        || path_str.contains("/.git/")
        || path_str.contains("/build/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_registers_all_passes() {
        let driver = AnalysisDriver::new();
        // 5 lints + 10 security checks = 15
        assert_eq!(driver.pass_count(), 15);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(Severity::Medium.to_string(), "medium");
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Info.to_string(), "info");
    }
}
