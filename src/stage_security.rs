use anyhow::Result;
use std::path::Path;

use crate::driver::AnalysisDriver;
use crate::types::SecurityResult;

/// Run the security scan stage using the syn-based analysis driver.
/// The driver walks all .rs files, parses them, and runs all registered
/// lint and security passes against them.
pub fn run(project_path: &Path, verbose: bool) -> Result<SecurityResult> {
    let mut result = SecurityResult::default();

    if verbose {
        eprintln!("[security] Running security analysis...");
    }

    let driver = AnalysisDriver::new();

    if verbose {
        eprintln!("[security] Registered {} analysis passes", driver.pass_count());
    }

    let findings = driver.analyze_project(project_path);

    if verbose {
        eprintln!("[security] Found {} issues", findings.len());
    }

    if !findings.is_empty() {
        result.pass = false;
        result.findings = findings;
    }

    Ok(result)
}
