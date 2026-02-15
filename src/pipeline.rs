use anyhow::Result;

use crate::config;
use crate::json_output;
use crate::stage_compile;
use crate::stage_security;
use crate::stage_supply_chain;
use crate::types::{
    CompileLintResult, PipelineReport, RunOptions, SecurityResult, StageFilter, SupplyChainResult,
};

/// Run the full UltraRust pipeline according to the given options.
/// Returns the aggregated pipeline report.
pub fn run(options: &RunOptions) -> Result<PipelineReport> {
    let config = config::load_config(
        &options.project_path,
        options.config_path.as_deref(),
    )?;

    if options.verbose {
        eprintln!("[pipeline] Project: {}", options.project_path.display());
        eprintln!("[pipeline] Config: {:?}", config);
    }

    // Stage 1: Supply Chain
    let supply_chain_result = if should_run_stage(&options.stage_filter, &StageFilter::SupplyChain)
        && config.supply_chain_checks
    {
        if options.verbose {
            eprintln!("[pipeline] === Stage 1: Supply Chain ===");
        }
        stage_supply_chain::run(&options.project_path, &config, options.verbose)?
    } else {
        if options.verbose {
            eprintln!("[pipeline] Skipping Stage 1 (supply chain)");
        }
        SupplyChainResult::default()
    };

    // Stage 2: Compile + Lint
    let compile_lint_result = if should_run_stage(&options.stage_filter, &StageFilter::Lint) {
        if options.verbose {
            eprintln!("[pipeline] === Stage 2: Compile + Lint ===");
        }
        stage_compile::run(&options.project_path, options.verbose)?
    } else {
        if options.verbose {
            eprintln!("[pipeline] Skipping Stage 2 (compile+lint)");
        }
        CompileLintResult::default()
    };

    // Stage 3: Security Scan
    let security_result = if should_run_stage(&options.stage_filter, &StageFilter::Security)
        && config.security_checks
    {
        if options.verbose {
            eprintln!("[pipeline] === Stage 3: Security Scan ===");
        }
        stage_security::run(&options.project_path, options.verbose)?
    } else {
        if options.verbose {
            eprintln!("[pipeline] Skipping Stage 3 (security)");
        }
        SecurityResult::default()
    };

    // Build the final report
    let report = json_output::build_report(supply_chain_result, compile_lint_result, security_result);

    // Output
    if options.json_output {
        let json = json_output::to_json(&report)?;
        println!("{}", json);
    } else {
        json_output::print_summary(&report, options.verbose);
    }

    Ok(report)
}

/// Determine if a particular stage should run based on the filter
fn should_run_stage(filter: &StageFilter, stage: &StageFilter) -> bool {
    match filter {
        StageFilter::All => true,
        other => other == stage,
    }
}
