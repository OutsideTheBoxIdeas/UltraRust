// UltraRusty: A hardened Rust pipeline for AI-generated code
// Entry point - cargo subcommand wrapper

mod config;
mod driver;
mod json_output;
mod lints;
mod pipeline;
mod security;
mod stage_compile;
mod stage_security;
mod stage_supply_chain;
mod types;

use clap::Parser;
use std::path::PathBuf;
use std::process;

use types::{RunOptions, StageFilter};

/// UltraRusty - A hardened Rust pipeline for AI-generated code.
///
/// Runs 3 stages: supply chain checks, compile+lint, and security analysis.
/// Outputs a pass/fail verdict with structured JSON reports.
#[derive(Parser, Debug)]
#[command(
    name = "ultrarusty",
    version,
    about = "A hardened Rust pipeline for AI-generated code"
)]
struct UltrarustyArgs {
    /// Path to the project to analyze (defaults to current directory)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Path to a custom configuration file
    #[arg(long = "config", short = 'c')]
    config_path: Option<PathBuf>,

    /// Output results as JSON to stdout
    #[arg(long = "json", short = 'j')]
    json: bool,

    /// Run only a specific stage
    #[arg(long = "stage", short = 's', value_parser = parse_stage_filter)]
    stage: Option<StageFilter>,

    /// Enable verbose output
    #[arg(long = "verbose", short = 'v')]
    verbose: bool,
}

fn parse_stage_filter(s: &str) -> Result<StageFilter, String> {
    match s {
        "supply-chain" | "supply_chain" | "sc" => Ok(StageFilter::SupplyChain),
        "lint" | "compile" | "compile-lint" => Ok(StageFilter::Lint),
        "security" | "sec" => Ok(StageFilter::Security),
        "all" => Ok(StageFilter::All),
        _ => Err(format!(
            "Unknown stage '{}'. Valid stages: supply-chain, lint, security, all",
            s
        )),
    }
}

fn main() {
    let args = UltrarustyArgs::parse();

    let project_path = if args.path.is_absolute() {
        args.path.clone()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(&args.path)
    };

    // Verify the project path exists and has a Cargo.toml
    if !project_path.join("Cargo.toml").exists() {
        eprintln!(
            "Error: No Cargo.toml found at {}",
            project_path.display()
        );
        eprintln!("Are you in a Rust project directory?");
        process::exit(1);
    }

    let options = RunOptions {
        project_path,
        config_path: args.config_path,
        json_output: args.json,
        stage_filter: args.stage.unwrap_or(StageFilter::All),
        verbose: args.verbose,
    };

    match pipeline::run(&options) {
        Ok(report) => {
            if report.pass {
                process::exit(0);
            } else {
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
            process::exit(2);
        }
    }
}
