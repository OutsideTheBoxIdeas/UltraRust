use anyhow::Result;

use crate::types::{
    CompileLintResult, Finding, PipelineReport, SecurityResult, Severity, SeverityCounts,
    StageResults, Summary, SupplyChainResult,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the full pipeline report from individual stage results
pub fn build_report(
    supply_chain: SupplyChainResult,
    compile_lint: CompileLintResult,
    security: SecurityResult,
) -> PipelineReport {
    let pass = supply_chain.pass && compile_lint.pass && security.pass;

    let mut all_findings: Vec<&Finding> = Vec::new();
    all_findings.extend(supply_chain.findings.iter());
    all_findings.extend(compile_lint.violations.iter());
    all_findings.extend(security.findings.iter());

    let summary = build_summary(&all_findings);

    PipelineReport {
        ultrarusty_version: VERSION.to_owned(),
        pass,
        stages: StageResults {
            supply_chain,
            compile_lint,
            security,
        },
        summary,
    }
}

/// Build summary statistics from all findings
fn build_summary(findings: &[&Finding]) -> Summary {
    let mut counts = SeverityCounts::default();

    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical = counts.critical.saturating_add(1),
            Severity::High => counts.high = counts.high.saturating_add(1),
            Severity::Medium => counts.medium = counts.medium.saturating_add(1),
            Severity::Low => counts.low = counts.low.saturating_add(1),
            Severity::Info => counts.low = counts.low.saturating_add(1),
        }
    }

    // "deny" level counts are compile_lint violations that don't map to a security severity
    // They show up as the total count minus what we already categorized
    let categorized = counts
        .critical
        .saturating_add(counts.high)
        .saturating_add(counts.medium)
        .saturating_add(counts.low);
    let total = findings.len();
    if total > categorized {
        counts.deny = total.saturating_sub(categorized);
    }

    Summary {
        total_issues: total,
        by_severity: counts,
    }
}

/// Serialize the report to a JSON string
pub fn to_json(report: &PipelineReport) -> Result<String> {
    let json = serde_json::to_string_pretty(report)?;
    Ok(json)
}

/// Print a human-readable summary to stderr
pub fn print_summary(report: &PipelineReport, verbose: bool) {
    let status = if report.pass { "PASS" } else { "FAIL" };
    eprintln!();
    eprintln!("=== UltraRusty v{} - {} ===", report.ultrarusty_version, status);
    eprintln!();

    // Supply chain
    let sc = &report.stages.supply_chain;
    let sc_status = if sc.pass { "PASS" } else { "FAIL" };
    eprintln!(
        "Stage 1 (Supply Chain): {} | vulns: {} | banned: {} | unsafe deps: {}",
        sc_status, sc.vulnerabilities, sc.banned_deps, sc.unsafe_in_deps
    );

    // Compile + lint
    let cl = &report.stages.compile_lint;
    let cl_status = if cl.pass { "PASS" } else { "FAIL" };
    eprintln!(
        "Stage 2 (Compile+Lint):  {} | violations: {}",
        cl_status,
        cl.violations.len()
    );

    // Security
    let sec = &report.stages.security;
    let sec_status = if sec.pass { "PASS" } else { "FAIL" };
    eprintln!(
        "Stage 3 (Security):     {} | findings: {}",
        sec_status,
        sec.findings.len()
    );

    eprintln!();
    eprintln!(
        "Total issues: {} (critical: {}, high: {}, medium: {}, low: {}, deny: {})",
        report.summary.total_issues,
        report.summary.by_severity.critical,
        report.summary.by_severity.high,
        report.summary.by_severity.medium,
        report.summary.by_severity.low,
        report.summary.by_severity.deny,
    );

    if verbose {
        print_findings_detail(report);
    }

    eprintln!();
}

/// Print detailed findings when verbose mode is on
fn print_findings_detail(report: &PipelineReport) {
    let all_violations = &report.stages.compile_lint.violations;
    let all_findings = &report.stages.security.findings;
    let sc_findings = &report.stages.supply_chain.findings;

    if !sc_findings.is_empty() {
        eprintln!();
        eprintln!("--- Supply Chain Issues ---");
        for f in sc_findings {
            print_finding(f);
        }
    }

    if !all_violations.is_empty() {
        eprintln!();
        eprintln!("--- Compile/Lint Violations ---");
        for f in all_violations {
            print_finding(f);
        }
    }

    if !all_findings.is_empty() {
        eprintln!();
        eprintln!("--- Security Findings ---");
        for f in all_findings {
            print_finding(f);
        }
    }
}

fn print_finding(f: &Finding) {
    eprintln!(
        "  [{severity}] {check} at {file}:{line}:{col}",
        severity = f.severity,
        check = f.check_name,
        file = f.file.display(),
        line = f.line,
        col = f.col,
    );
    eprintln!("    {}", f.message);
    if !f.snippet.is_empty() {
        eprintln!("    > {}", f.snippet);
    }
    if !f.fix.is_empty() {
        eprintln!("    fix: {}", f.fix);
    }
}
