# UltraRusty Architecture Spec

This document defines the shared types, module contracts, and data flow for UltraRusty.
Two builder teams implement against these interfaces. If it is not in this spec, it is
an implementation detail the builder decides.

---

## Critical Design Note: syn-based Analysis, Not rustc_driver

The build plan mentions `rustc_driver::Callbacks`, but the project uses **stable Rust**
with `syn` for source analysis. All custom lints and security checks are implemented as
`syn::visit::Visit` traversals over parsed ASTs, NOT as compiler plugins. The `driver.rs`
module orchestrates `syn`-based analysis passes, not a rustc driver.

This means:
- Custom lints operate on `syn::File` ASTs, not HIR/MIR
- Security checks use `syn::visit::Visit` trait, same as lints
- No nightly Rust required
- Trade-off: no type information (heuristic name-based matching for security checks)

---

## 1. Shared Types (`src/config.rs`)

All shared types live in `config.rs`. Every other module imports from here.

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─── Configuration ───

/// Read from target project's `Cargo.toml` under `[package.metadata.ultrarusty]`.
/// All fields optional with defaults shown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UltraRustyConfig {
    pub max_complexity: u32,             // default: 12
    pub max_function_lines: u32,         // default: 80
    pub max_parameters: u32,             // default: 5
    pub max_generic_params: u32,         // default: 4
    pub max_nesting: u32,                // default: 4
    pub geiger_unsafe_threshold: u32,    // default: 0 (direct deps)
    pub geiger_transitive_threshold: u32,// default: 50
    pub security_checks: bool,           // default: true
    pub supply_chain_checks: bool,       // default: true
}

impl Default for UltraRustyConfig {
    fn default() -> Self {
        Self {
            max_complexity: 12,
            max_function_lines: 80,
            max_parameters: 5,
            max_generic_params: 4,
            max_nesting: 4,
            geiger_unsafe_threshold: 0,
            geiger_transitive_threshold: 50,
            security_checks: true,
            supply_chain_checks: true,
        }
    }
}

// ─── Severity ───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

// ─── Source Location ───

/// Points to a specific location in a source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: usize,
    pub col: usize,
}

// ─── Finding (used by custom lints AND security checks) ───

/// A single issue found by a custom lint or security check.
/// This is the universal type for all syn-based analysis output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub check: String,            // e.g. "ultrarusty::no_interior_mutability" or "hardcoded_secret"
    pub severity: Severity,
    pub location: SourceLocation,
    pub message: String,          // human-readable description
    pub snippet: String,          // the offending source line(s)
    pub fix: String,              // suggested fix
}

// ─── Violation (for clippy/compile stage output) ───

/// A violation from rustc or clippy (parsed from their JSON output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub source: ViolationSource,
    pub lint: String,             // e.g. "clippy::unwrap_used"
    pub level: String,            // e.g. "deny", "error"
    pub location: SourceLocation,
    pub message: String,
    pub snippet: String,
    pub fix: String,              // suggested fix, may be empty
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViolationSource {
    Rustc,
    Clippy,
}

// ─── Stage Results ───

/// Result of Stage 1: Supply Chain checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainResult {
    pub pass: bool,
    pub vulnerabilities: u32,     // from cargo-audit
    pub banned_deps: u32,         // from cargo-deny
    pub license_violations: u32,  // from cargo-deny
    pub unsafe_in_deps: u32,      // from cargo-geiger
    pub details: Vec<String>,     // human-readable detail lines
}

/// Result of Stage 2: Compile + Lint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileLintResult {
    pub pass: bool,
    pub violations: Vec<Violation>,
    pub custom_findings: Vec<Finding>, // from the 5 custom lints
}

/// Result of Stage 3: Security Scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityResult {
    pub pass: bool,
    pub findings: Vec<Finding>,
}

/// Wraps all three stage results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    pub pass: bool,
    pub supply_chain: Option<SupplyChainResult>,  // None if skipped
    pub compile_lint: CompileLintResult,
    pub security: Option<SecurityResult>,          // None if skipped
}

// ─── Final Report (JSON output) ───

/// The top-level JSON report written to stdout or a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltraRustyReport {
    pub ultrarusty_version: String,
    pub pass: bool,
    pub stages: StagesReport,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagesReport {
    pub supply_chain: Option<SupplyChainStageReport>,
    pub compile_lint: CompileLintStageReport,
    pub security: Option<SecurityStageReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainStageReport {
    pub pass: bool,
    pub vulnerabilities: u32,
    pub banned_deps: u32,
    pub license_violations: u32,
    pub unsafe_in_deps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileLintStageReport {
    pub pass: bool,
    pub violations: Vec<Violation>,
    pub custom_findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStageReport {
    pub pass: bool,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total_issues: u32,
    pub by_severity: BTreeMap<String, u32>,  // "critical" -> 1, "deny" -> 2
}

// ─── Analysis Pass Trait (for driver.rs) ───

/// Every custom lint and security check implements this trait.
/// The driver calls `analyze` on each pass for each source file.
pub trait AnalysisPass {
    /// Human-readable name, e.g. "no_interior_mutability" or "hardcoded_secrets".
    fn name(&self) -> &'static str;

    /// Run analysis on a single parsed source file.
    /// `file_path` is the path on disk (for SourceLocation).
    /// `syntax` is the parsed `syn::File`.
    /// Returns zero or more findings.
    fn analyze(&self, file_path: &std::path::Path, syntax: &syn::File) -> Vec<Finding>;
}
```

**Use `std::collections::BTreeMap`** for `by_severity` (not HashMap -- deterministic ordering).

---

## 2. Module Contracts

### `src/config.rs` -- Configuration & Shared Types

**Responsibilities**: Parse config from target Cargo.toml, embed default config files, export all shared types.

```rust
// ── Public API ──

/// All shared types above are defined and exported here.

/// Parse UltraRustyConfig from the target project's Cargo.toml.
/// Reads `[package.metadata.ultrarusty]` section.
/// Returns Default if section is missing.
/// `project_dir` is the root of the project being analyzed.
pub fn load_config(project_dir: &Path) -> anyhow::Result<UltraRustyConfig>;

/// Write the embedded clippy_config.toml to a temp path and return that path.
/// The caller passes this path to clippy via `CLIPPY_CONF_DIR`.
pub fn write_clippy_config(tmp_dir: &Path) -> anyhow::Result<PathBuf>;

/// Write the embedded deny_config.toml to a temp path and return that path.
/// The caller passes this path to `cargo deny --config <path>`.
pub fn write_deny_config(tmp_dir: &Path) -> anyhow::Result<PathBuf>;
```

**Constraint**: Use `include_str!` to embed `config/clippy_config.toml` and `config/deny_config.toml` at compile time.

---

### `src/pipeline.rs` -- Pipeline Orchestration

**Responsibilities**: Run stages in sequence, short-circuit on failure (optional), aggregate into `PipelineResult`.

```rust
use crate::config::{UltraRustyConfig, PipelineResult};

/// Run the full 3-stage pipeline against the project at `project_dir`.
/// Stages run in order: supply_chain -> compile_lint -> security.
/// All stages run regardless of earlier failures (no short-circuit) so the
/// report contains ALL issues for the AI to fix in one pass.
/// Returns the aggregated result.
pub fn run_pipeline(project_dir: &Path, config: &UltraRustyConfig) -> anyhow::Result<PipelineResult>;
```

**Constraints**:
- Must call `stage_supply_chain::run()`, `stage_compile::run()`, `stage_security::run()` in that order.
- If `config.supply_chain_checks` is false, skip Stage 1 (set `supply_chain` to `None`).
- If `config.security_checks` is false, skip Stage 3 (set `security` to `None`).
- `pass` is true only if ALL executed stages pass.
- Does NOT produce JSON -- that is `json_output`'s job.

---

### `src/stage_supply_chain.rs` -- Stage 1: Supply Chain

**Responsibilities**: Shell out to cargo-audit, cargo-deny, cargo-geiger. Parse their output. Return `SupplyChainResult`.

```rust
use crate::config::{UltraRustyConfig, SupplyChainResult};

/// Run all supply chain checks against the project at `project_dir`.
/// Requires cargo-audit, cargo-deny, and cargo-geiger to be installed.
/// If a tool is not installed, its sub-check fails with a message in `details`.
pub fn run(project_dir: &Path, config: &UltraRustyConfig) -> anyhow::Result<SupplyChainResult>;
```

**Constraints**:
- Run `cargo audit --json` in `project_dir`, parse JSON stdout for vulnerability count.
- Run `cargo deny --config <deny_config_path> check` in `project_dir`, parse exit code + stderr.
- Run `cargo geiger --output-format json` in `project_dir`, parse JSON for unsafe counts.
- Compare geiger counts against `config.geiger_unsafe_threshold` and `config.geiger_transitive_threshold`.
- `pass` is true only if ALL three sub-checks pass.
- Use `which::which()` to check tool availability before running.
- Use `std::process::Command` to execute (UltraRusty itself is allowed to use Command -- the ban is for analyzed code).

---

### `src/stage_compile.rs` -- Stage 2: Compile + Lint

**Responsibilities**: Run `cargo clippy` with the full lint config + RUSTFLAGS. Parse JSON output into `Violation`s. Also run the 5 custom lints via the driver. Return `CompileLintResult`.

```rust
use crate::config::{UltraRustyConfig, CompileLintResult};

/// Run compile + lint checks on the project at `project_dir`.
/// 1. Run `cargo clippy` with RUSTFLAGS and clippy config.
/// 2. Run the 5 custom UltraRusty lints via `driver::run_analysis`.
/// Combine results into CompileLintResult.
pub fn run(project_dir: &Path, config: &UltraRustyConfig) -> anyhow::Result<CompileLintResult>;
```

**Constraints**:
- Set `RUSTFLAGS="-D warnings -D unsafe-code -D unused -D nonstandard-style -D future-incompatible"`.
- Set `CLIPPY_CONF_DIR` to the temp dir containing the embedded `clippy.toml`.
- Run `cargo clippy --message-format=json -- <all deny flags>` where `<all deny flags>` is the ~70 `-D clippy::xxx` flags from the build plan.
- Parse each JSON line from clippy stdout. Lines with `"reason":"compiler-message"` contain the diagnostics.
- Map clippy JSON messages to `Violation` structs.
- Call `driver::run_analysis()` with only the 5 custom lint passes (not security passes).
- `pass` is true if zero violations AND zero custom findings.

---

### `src/stage_security.rs` -- Stage 3: Security Scan

**Responsibilities**: Run the 10 security checks via the driver. Return `SecurityResult`.

```rust
use crate::config::{UltraRustyConfig, SecurityResult};

/// Run security analysis on the project at `project_dir`.
/// Uses `driver::run_analysis` with all 10 security analysis passes.
pub fn run(project_dir: &Path, config: &UltraRustyConfig) -> anyhow::Result<SecurityResult>;
```

**Constraints**:
- Call `driver::run_analysis()` with the 10 security passes.
- `pass` is true if zero findings.

---

### `src/driver.rs` -- Analysis Driver

**Responsibilities**: Walk `.rs` source files, parse each with `syn`, run analysis passes, collect findings.

```rust
use crate::config::{Finding, AnalysisPass};
use std::path::Path;

/// Walk all `.rs` files under `project_dir/src/`, parse each with syn,
/// run every analysis pass, and return all findings.
///
/// Skips files that fail to parse (logs a warning, does not fail the whole run).
/// Does NOT walk the `target/` directory.
pub fn run_analysis(
    project_dir: &Path,
    passes: &[Box<dyn AnalysisPass>],
) -> anyhow::Result<Vec<Finding>>;
```

**Constraints**:
- Use `walkdir::WalkDir` to find `.rs` files.
- Skip any path containing `/target/`.
- Parse with `syn::parse_file()`. On parse failure, push a `Finding` with severity `Info` and message "Failed to parse: {error}" -- do not abort.
- For each successfully parsed file, call `pass.analyze(file_path, &syntax)` for every pass.
- Return the concatenation of all findings from all passes on all files.

---

### `src/json_output.rs` -- JSON Report

**Responsibilities**: Convert `PipelineResult` into `UltraRustyReport` and serialize to JSON.

```rust
use crate::config::{PipelineResult, UltraRustyReport};

/// Build the final report from pipeline results.
pub fn build_report(result: &PipelineResult) -> UltraRustyReport;

/// Serialize report to pretty-printed JSON string.
pub fn to_json(report: &UltraRustyReport) -> anyhow::Result<String>;
```

**Constraints**:
- `ultrarusty_version` comes from `env!("CARGO_PKG_VERSION")`.
- `summary.total_issues` = count of all violations + all findings across all stages.
- `summary.by_severity` aggregates counts. Violations get keyed by their `level` field. Findings get keyed by their `severity` field (lowercased).
- Use `serde_json::to_string_pretty`.

---

### `src/main.rs` -- Entry Point

**Responsibilities**: Parse CLI args, load config, run pipeline, output report.

```rust
use clap::Parser;

/// cargo-ultrarusty: A hardened Rust pipeline for AI-generated code.
/// Invoked as `cargo ultrarusty [OPTIONS]`.
#[derive(Parser, Debug)]
#[command(name = "cargo-ultrarusty", bin_name = "cargo-ultrarusty")]
pub struct Cli {
    /// When invoked as `cargo ultrarusty`, cargo passes "ultrarusty" as first arg.
    /// This captures and ignores that.
    #[arg(hide = true, default_value = "ultrarusty")]
    _subcommand: String,

    /// Path to the project to analyze. Defaults to current directory.
    #[arg(short, long, default_value = ".")]
    pub project_dir: PathBuf,

    /// Output format: "json" (default) or "human".
    #[arg(short, long, default_value = "json")]
    pub format: OutputFormat,

    /// Write report to file instead of stdout.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Human,
}
```

**Constraints**:
- Parse args with `Cli::parse()`.
- Call `config::load_config()`.
- Call `pipeline::run_pipeline()`.
- Call `json_output::build_report()` + `json_output::to_json()`.
- Print to stdout or write to `--output` file.
- Exit with code 0 if pass, 1 if fail.
- If format is `human`, print a colored summary using `colored` crate (violations/findings as a table). Still exit 0/1.

---

### `src/lints/mod.rs` -- Custom Lint Registration

```rust
use crate::config::AnalysisPass;

/// Return all 5 custom lint passes, boxed.
pub fn all_lint_passes() -> Vec<Box<dyn AnalysisPass>>;
```

Each sub-module (`no_interior_mut.rs`, etc.) exports a struct that implements `AnalysisPass`.

---

### `src/security/mod.rs` -- Security Check Registration

```rust
use crate::config::AnalysisPass;

/// Return all 10 security check passes, boxed.
pub fn all_security_passes() -> Vec<Box<dyn AnalysisPass>>;
```

Each sub-module (`hardcoded_secrets.rs`, etc.) exports a struct that implements `AnalysisPass`.

---

## 3. Individual Lint & Security Check Contracts

Each check is a struct implementing `AnalysisPass`. Below are the struct names and what they detect.

### Custom Lints (5)

| File | Struct | `name()` | Detects | Severity |
|------|--------|----------|---------|----------|
| `no_interior_mut.rs` | `NoInteriorMutability` | `"no_interior_mutability"` | Type paths containing `RefCell`, `Cell`, or `UnsafeCell` in any position (field types, local variable types, function return types) | `High` |
| `no_string_errors.rs` | `NoStringErrors` | `"no_string_errors"` | `Result<_, String>` or `Result<_, &str>` as return types or type aliases | `Medium` |
| `no_infinite_loops.rs` | `NoInfiniteLoops` | `"no_infinite_loops"` | `loop { }` blocks where there is no `break` expression anywhere inside the loop body (AST search) | `High` |
| `public_api_lifetimes.rs` | `PublicApiLifetimes` | `"public_api_lifetimes"` | `pub fn` or `pub(crate) fn` with reference parameters or reference return types that use elided lifetimes | `Medium` |
| `bounded_generics.rs` | `BoundedGenerics` | `"bounded_generics"` | Functions or types with more than `max_generic_params` (default 4) type parameters | `Low` |

**Implementation pattern for all lints**:

```rust
pub struct NoInteriorMutability;

impl AnalysisPass for NoInteriorMutability {
    fn name(&self) -> &'static str { "no_interior_mutability" }

    fn analyze(&self, file_path: &Path, syntax: &syn::File) -> Vec<Finding> {
        let mut visitor = InteriorMutVisitor {
            findings: Vec::new(),
            file_path: file_path.to_path_buf(),
        };
        syn::visit::visit_file(&mut visitor, syntax);
        visitor.findings
    }
}

struct InteriorMutVisitor {
    findings: Vec<Finding>,
    file_path: PathBuf,
}

impl<'ast> syn::visit::Visit<'ast> for InteriorMutVisitor {
    // Override visit_type_path, visit_field, etc.
}
```

### Security Checks (10)

| File | Struct | `name()` | Detects | Severity | Strategy |
|------|--------|----------|---------|----------|----------|
| `hardcoded_secrets.rs` | `HardcodedSecrets` | `"hardcoded_secret"` | String literals matching secret patterns (`sk-`, `AKIA`, `ghp_`, `password=`, etc.) or high Shannon entropy (>4.5) strings longer than 16 chars | `Critical` | Visit `Expr::Lit(Lit::Str)` nodes, apply regex + entropy check |
| `command_injection.rs` | `CommandInjection` | `"command_injection"` | Method calls to `.arg()` or `.args()` on expressions that look like Command builders, where the argument is a function parameter (name-based heuristic) | `Critical` | Visit method calls, check if receiver chain includes `Command::new` or `command()`, check if arg is a fn param ident |
| `path_traversal.rs` | `PathTraversal` | `"path_traversal"` | Calls to `Path::join()`, `PathBuf::push()`, `Path::new()` where the argument is a function parameter | `High` | Visit method calls named `join`/`push`/`new` on Path-like receivers, check if arg is fn param |
| `weak_crypto.rs` | `WeakCrypto` | `"weak_crypto"` | Use paths containing `md5`, `sha1`, `rc4`, `des`, `ecb` (case-insensitive) in use statements or function calls | `High` | Visit `use` items and path expressions, check segments against ban list |
| `insecure_deser.rs` | `InsecureDeser` | `"insecure_deser"` | Calls to `serde_json::from_str`, `serde_json::from_reader`, `serde_json::from_slice`, `bincode::deserialize` without nearby size/limit checks | `Medium` | Visit function calls matching deser paths |
| `sql_injection.rs` | `SqlInjection` | `"sql_injection"` | `format!()` macro output flowing into method calls named `query`, `execute`, `prepare`, or variables named `sql`/`query` | `Critical` | Visit `let` bindings where init is `format!()` and name contains `sql`/`query`, or method calls named `query`/`execute` with `format!()` args |
| `unbounded_reads.rs` | `UnboundedReads` | `"unbounded_read"` | Method calls to `read_to_string()` or `read_to_end()` | `Medium` | Visit method calls, match name |
| `insecure_tls.rs` | `InsecureTls` | `"insecure_tls"` | Method calls to `danger_accept_invalid_certs`, `danger_accept_invalid_hostnames`, `set_verify(SslVerifyMode::NONE)` | `Critical` | Visit method calls, match name |
| `insecure_random.rs` | `InsecureRandom` | `"insecure_random"` | Calls to `thread_rng()` or `random()` from `rand` crate within functions whose name or context includes security-related identifiers (`token`, `key`, `secret`, `password`, `auth`, `crypt`, `hash`, `session`) | `High` | Visit function calls, check enclosing fn name |
| `timing_attack.rs` | `TimingAttack` | `"timing_attack"` | Binary `==` or `!=` comparisons where either operand is a variable named `token`, `secret`, `key`, `hash`, `password`, `digest`, `signature`, `hmac` | `High` | Visit `Expr::Binary` with `Eq`/`Ne` ops, check ident names |

---

## 4. Data Flow

```
main.rs
  |
  |-- config::load_config(project_dir) -> UltraRustyConfig
  |
  |-- pipeline::run_pipeline(project_dir, &config) -> PipelineResult
  |     |
  |     |-- [if config.supply_chain_checks]
  |     |   stage_supply_chain::run(project_dir, &config) -> SupplyChainResult
  |     |     |-- shells out to: cargo audit, cargo deny, cargo geiger
  |     |     |-- parses their JSON/text output
  |     |
  |     |-- stage_compile::run(project_dir, &config) -> CompileLintResult
  |     |     |-- config::write_clippy_config(tmp) -> clippy.toml path
  |     |     |-- shells out to: cargo clippy --message-format=json
  |     |     |-- parses JSON lines into Vec<Violation>
  |     |     |-- lints::all_lint_passes() -> Vec<Box<dyn AnalysisPass>>
  |     |     |-- driver::run_analysis(project_dir, &lint_passes) -> Vec<Finding>
  |     |
  |     |-- [if config.security_checks]
  |         stage_security::run(project_dir, &config) -> SecurityResult
  |           |-- security::all_security_passes() -> Vec<Box<dyn AnalysisPass>>
  |           |-- driver::run_analysis(project_dir, &security_passes) -> Vec<Finding>
  |
  |-- json_output::build_report(&pipeline_result) -> UltraRustyReport
  |-- json_output::to_json(&report) -> String
  |-- print to stdout or write to --output file
  |-- exit(0) if pass, exit(1) if fail
```

---

## 5. Constraints for Builders

1. **All public types are in `config.rs`**. Do not define pipeline-visible types elsewhere.
2. **Use `anyhow::Result` for all fallible public functions**. Internal errors bubble up; lint/security failures are data (findings), not errors.
3. **Never panic**. Use `?` for errors. The pipeline must always produce a report, even if tools are missing.
4. **`BTreeMap` not `HashMap`** for any map in serialized output (deterministic JSON).
5. **All file paths in `Finding`/`Violation` must be relative to `project_dir`**. Strip the prefix before storing.
6. **Snippets**: Read the source line from the file at the location. The `driver` should pass file contents alongside the parsed AST so visitors can extract snippets without re-reading.
7. **`AnalysisPass` must be `Send + Sync`** (the trait should have these as supertraits) to allow future parallelization. All 15 check structs are stateless unit structs.
8. **Security checks are heuristic**. Name-based matching is acceptable. Do not attempt whole-program analysis.
9. **Clippy flags**: The full list of `-D clippy::xxx` flags must be built as a `Vec<String>` in `stage_compile.rs`. Keep them in a const array for maintainability.
10. **Exit codes from shelled-out tools**: Non-zero exit from `cargo clippy`, `cargo audit`, `cargo deny` means issues were found (not a tool failure). Parse output regardless of exit code.
11. **Temp directory**: `pipeline.rs` creates one `tempfile::TempDir` for the whole run and passes its path to stages that need to write config files. The TempDir is held alive for the pipeline duration.
12. **Version**: Use `env!("CARGO_PKG_VERSION")` -- do not hardcode "1.0.0".

---

## 6. Updated `AnalysisPass` Trait (final form)

```rust
/// Every custom lint and security check implements this trait.
/// Must be Send + Sync for future parallelization.
pub trait AnalysisPass: Send + Sync {
    /// Check name, e.g. "no_interior_mutability" or "hardcoded_secret".
    fn name(&self) -> &'static str;

    /// Run analysis on one source file.
    /// `file_path` - path relative to project root.
    /// `source` - raw source text (for snippet extraction).
    /// `syntax` - parsed syn::File.
    fn analyze(
        &self,
        file_path: &std::path::Path,
        source: &str,
        syntax: &syn::File,
    ) -> Vec<Finding>;
}
```

Note: Added `source: &str` parameter compared to the earlier definition. The driver reads the file, parses it, and passes both the raw text and the AST to each pass. This lets passes extract snippets by line number without re-reading the file.

Updated `driver::run_analysis` signature:

```rust
pub fn run_analysis(
    project_dir: &Path,
    passes: &[Box<dyn AnalysisPass>],
) -> anyhow::Result<Vec<Finding>>;
```

The driver internally:
1. Walks `.rs` files under `project_dir` (excluding `target/`).
2. For each file, reads contents with `std::fs::read_to_string`.
3. Parses with `syn::parse_file(&source)`.
4. Computes relative path: `file_path.strip_prefix(project_dir)`.
5. Calls `pass.analyze(&relative_path, &source, &syntax)` for each pass.
6. Collects and returns all findings.

---

## 7. Helper: Snippet Extraction

Builders should use this utility (can live in `config.rs` or `driver.rs`):

```rust
/// Extract the source line at `line` (1-indexed) from `source`.
/// Returns the trimmed line, or "<source unavailable>" if out of range.
pub fn extract_snippet(source: &str, line: usize) -> String {
    source
        .lines()
        .nth(line.saturating_sub(1))
        .map(|l| l.trim().to_owned())
        .unwrap_or_else(|| "<source unavailable>".to_owned())
}
```

---

## 8. Getting `line` and `col` from `syn` Spans

`syn` spans give line/column info via `span.start()` when the `proc-macro2` crate's `span-locations` feature is enabled. **Builders must add this to Cargo.toml**:

```toml
proc-macro2 = { version = "1", features = ["span-locations"] }
```

Then in visitor code:

```rust
let span = node.span();
let start = span.start();
let line = start.line;   // 1-indexed
let col = start.column;  // 0-indexed
```

This is already implied by the skeleton's `proc-macro2 = "1"` dependency but the `span-locations` feature **must** be added or all spans will report line 0, column 0.
