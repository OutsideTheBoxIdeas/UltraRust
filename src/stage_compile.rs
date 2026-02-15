use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config;
use crate::types::{CompileLintResult, Finding, Severity};

/// The full list of clippy lints to enable at deny level
const CLIPPY_DENY_LINTS: &[&str] = &[
    // SAFETY: Prevent runtime panics
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::panic",
    "clippy::panic_in_result_fn",
    "clippy::todo",
    "clippy::unimplemented",
    "clippy::unreachable",
    "clippy::indexing_slicing",
    "clippy::string_slice",
    "clippy::modulo_arithmetic",
    "clippy::exit",
    // SAFETY: Prevent memory/type unsoundness
    "clippy::as_conversions",
    "clippy::cast_possible_truncation",
    "clippy::cast_sign_loss",
    "clippy::cast_possible_wrap",
    "clippy::cast_lossless",
    "clippy::cast_precision_loss",
    "clippy::fn_to_numeric_cast",
    "clippy::ptr_as_ptr",
    "clippy::mem_forget",
    "clippy::multiple_unsafe_ops_per_block",
    "clippy::undocumented_unsafe_blocks",
    "clippy::transmute_int_to_float",
    "clippy::transmute_ptr_to_ref",
    // SAFETY: Prevent arithmetic bugs
    "clippy::arithmetic_side_effects",
    "clippy::integer_division",
    "clippy::float_cmp",
    "clippy::float_cmp_const",
    "clippy::float_arithmetic",
    "clippy::lossy_float_literal",
    // ERROR HANDLING: Force proper error management
    "clippy::let_underscore_must_use",
    "clippy::try_err",
    "clippy::map_err_ignore",
    "clippy::result_large_err",
    // CODE QUALITY: Force clean, efficient code
    "clippy::cognitive_complexity",
    "clippy::too_many_arguments",
    "clippy::too_many_lines",
    "clippy::excessive_nesting",
    "clippy::wildcard_enum_match_arm",
    "clippy::match_wildcard_for_single_variants",
    "clippy::redundant_clone",
    "clippy::clone_on_ref_ptr",
    "clippy::shadow_reuse",
    "clippy::shadow_unrelated",
    "clippy::same_name_method",
    "clippy::rest_pat_in_fully_bound_structs",
    "clippy::unneeded_field_pattern",
    "clippy::empty_structs_with_brackets",
    "clippy::large_types_passed_by_value",
    "clippy::needless_pass_by_value",
    "clippy::unnecessary_wraps",
    "clippy::unused_self",
    // PRODUCTION HYGIENE: No debug/dev artifacts
    "clippy::dbg_macro",
    "clippy::print_stdout",
    "clippy::print_stderr",
    "clippy::use_debug",
    "clippy::allow_attributes",
    // DOCUMENTATION
    "clippy::missing_docs_in_private_items",
    "clippy::missing_errors_doc",
    "clippy::missing_panics_doc",
    "clippy::missing_safety_doc",
    // EFFICIENCY
    "clippy::str_to_string",
    "clippy::verbose_file_reads",
    "clippy::rc_buffer",
    "clippy::rc_mutex",
    "clippy::mutex_atomic",
    "clippy::trivially_copy_pass_by_ref",
    "clippy::large_stack_arrays",
    "clippy::large_stack_frames",
    "clippy::disallowed_methods",
    "clippy::disallowed_types",
];

/// Run the compile + lint stage on the target project
pub fn run(project_path: &Path, verbose: bool) -> Result<CompileLintResult> {
    let mut result = CompileLintResult::default();

    if verbose {
        eprintln!("[compile-lint] Running compile + lint checks...");
    }

    // Write the clippy config to the project
    let clippy_config_path = config::write_clippy_config(project_path)?;

    // Build the -W flags for all our lints
    let warn_flags: Vec<String> = CLIPPY_DENY_LINTS
        .iter()
        .map(|lint| format!("-W {}", lint))
        .collect();
    let warn_flags_str = warn_flags.join(" ");

    // RUSTFLAGS for compiler-level denials
    let rustflags = format!(
        "-D warnings -D unsafe-code -D unused -D nonstandard-style \
         -D future-incompatible {}",
        warn_flags_str
    );

    if verbose {
        eprintln!("[compile-lint] RUSTFLAGS: {}", rustflags);
    }

    // Run clippy with JSON output
    let mut cmd = Command::new("cargo");
    cmd.arg("clippy")
        .arg("--message-format=json")
        .arg("--all-targets")
        .arg("--")
        .args(
            CLIPPY_DENY_LINTS
                .iter()
                .flat_map(|lint| ["-D", lint]),
        )
        .env("RUSTFLAGS", "-D warnings -D unsafe-code -D unused -D nonstandard-style -D future-incompatible")
        .env("CLIPPY_CONF_DIR", clippy_config_path.parent().unwrap_or(project_path))
        .current_dir(project_path);

    if verbose {
        eprintln!("[compile-lint] Running: cargo clippy ...");
    }

    let output = cmd.output().context("Failed to execute cargo clippy")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON output lines from clippy
    let violations = parse_clippy_json(&stdout)?;

    if !violations.is_empty() {
        result.pass = false;
        result.violations = violations;
    }

    // Cleanup temporary config
    let _ = std::fs::remove_file(&clippy_config_path);

    Ok(result)
}

/// Parse clippy's JSON message output into findings
fn parse_clippy_json(output: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }

        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Only process compiler messages (not artifact notifications)
        let reason = value.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        if reason != "compiler-message" {
            continue;
        }

        let message = match value.get("message") {
            Some(m) => m,
            None => continue,
        };

        let level = message
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Only collect errors and warnings (which are promoted to errors)
        if level != "error" && level != "warning" {
            continue;
        }

        let msg_text = message
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        let code = message
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_owned();

        // Extract primary span info
        let (file, line_num, col_num, snippet) =
            extract_primary_span(message.get("spans").and_then(|s| s.as_array()));

        // Extract suggested fix from children
        let fix = extract_suggestion(message.get("children").and_then(|c| c.as_array()));

        let severity = match level {
            "error" => Severity::High,
            _ => Severity::Medium,
        };

        findings.push(Finding {
            source: "clippy".to_owned(),
            check_name: code,
            severity,
            file,
            line: line_num,
            col: col_num,
            message: msg_text,
            snippet,
            fix,
        });
    }

    Ok(findings)
}

/// Extract file, line, col, and snippet from the primary span
fn extract_primary_span(spans: Option<&Vec<serde_json::Value>>) -> (PathBuf, usize, usize, String) {
    let spans = match spans {
        Some(s) => s,
        None => return (PathBuf::new(), 0, 0, String::new()),
    };

    // Find the primary span, or use the first one
    let primary = spans
        .iter()
        .find(|s| {
            s.get("is_primary")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .or_else(|| spans.first());

    match primary {
        Some(span) => {
            let file = PathBuf::from(
                span.get("file_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            );
            let line = span
                .get("line_start")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let col = span
                .get("column_start")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let snippet = span
                .get("text")
                .and_then(|t| t.as_array())
                .and_then(|arr| arr.first())
                .and_then(|first| first.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_owned();

            (file, line, col, snippet)
        }
        None => (PathBuf::new(), 0, 0, String::new()),
    }
}

/// Extract a suggested fix from compiler message children
fn extract_suggestion(children: Option<&Vec<serde_json::Value>>) -> String {
    let children = match children {
        Some(c) => c,
        None => return String::new(),
    };

    for child in children {
        let level = child
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if level == "help" || level == "note" {
            if let Some(msg) = child.get("message").and_then(|v| v.as_str()) {
                // Check if there's a suggested replacement
                if let Some(spans) = child.get("spans").and_then(|s| s.as_array()) {
                    for span in spans {
                        if let Some(replacement) =
                            span.get("suggested_replacement").and_then(|v| v.as_str())
                        {
                            if !replacement.is_empty() {
                                return replacement.to_owned();
                            }
                        }
                    }
                }
                return msg.to_owned();
            }
        }
    }

    String::new()
}
