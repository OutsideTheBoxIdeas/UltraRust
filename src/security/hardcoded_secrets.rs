// Detect API keys, passwords, tokens in string literals
// Uses regex patterns for known key formats and Shannon entropy for high-entropy strings.

use std::path::Path;

use regex::Regex;
use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

/// Known secret patterns: (name, regex pattern)
const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("GitHub Personal Access Token", r"ghp_[a-zA-Z0-9]{36}"),
    ("GitHub OAuth Token", r"gho_[a-zA-Z0-9]{36}"),
    ("GitHub App Token", r"ghu_[a-zA-Z0-9]{36}"),
    ("OpenAI API Key", r"sk-[a-zA-Z0-9]{20,}"),
    ("Slack Token", r"xox[baprs]-[a-zA-Z0-9\-]{10,}"),
    ("Stripe Secret Key", r"sk_live_[a-zA-Z0-9]{20,}"),
    ("Stripe Publishable Key", r"pk_live_[a-zA-Z0-9]{20,}"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Heroku API Key", r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    ("Generic Password Assignment", r#"(?i)(password|passwd|pwd)\s*=\s*['"][^'"]{4,}['"]"#),
    ("Generic Secret Assignment", r#"(?i)(secret|api_key|apikey|access_token|auth_token)\s*=\s*['"][^'"]{4,}['"]"#),
    ("Private Key Header", r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    ("Bearer Token", r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]{20,}"),
];

/// Minimum string length to check for high-entropy secrets.
const MIN_ENTROPY_STRING_LEN: usize = 20;

/// Shannon entropy threshold for flagging strings.
const ENTROPY_THRESHOLD: f64 = 4.5;

pub struct HardcodedSecrets {
    patterns: Vec<(String, Regex)>,
}

impl HardcodedSecrets {
    pub fn new() -> Self {
        let patterns = SECRET_PATTERNS
            .iter()
            .filter_map(|(name, pattern)| {
                Regex::new(pattern).ok().map(|r| (name.to_string(), r))
            })
            .collect();
        HardcodedSecrets { patterns }
    }
}

impl AnalysisPass for HardcodedSecrets {
    fn name(&self) -> &str {
        "hardcoded_secrets"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = SecretVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
            patterns: &self.patterns,
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct SecretVisitor<'a> {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
    patterns: &'a [(String, Regex)],
}

impl SecretVisitor<'_> {
    fn check_string_literal(&mut self, value: &str, span: proc_macro2::Span) {
        // Check against known patterns
        for (name, regex) in self.patterns {
            if regex.is_match(value) {
                self.findings.push(Finding {
                    source: "security".into(),
                    check_name: "hardcoded_secrets".into(),
                    severity: Severity::Critical,
                    file: self.path.clone(),
                    line: span.start().line,
                    col: span.start().column,
                    message: format!("Hardcoded {} detected in string literal.", name),
                    snippet: truncate_secret(value),
                    fix: "Load from environment variable or secret manager. Never hardcode secrets.".into(),
                });
                return; // One finding per string is enough
            }
        }

        // Check for high-entropy strings (potential secrets)
        if value.len() >= MIN_ENTROPY_STRING_LEN {
            let entropy = shannon_entropy(value);
            if entropy > ENTROPY_THRESHOLD {
                // Filter out common false positives
                if !is_likely_false_positive(value) {
                    self.findings.push(Finding {
                        source: "security".into(),
                        check_name: "hardcoded_secrets".into(),
                        severity: Severity::High,
                        file: self.path.clone(),
                        line: span.start().line,
                        col: span.start().column,
                        message: format!(
                            "High-entropy string detected (entropy: {:.2}). Possible hardcoded secret.",
                            entropy
                        ),
                        snippet: truncate_secret(value),
                        fix: "If this is a secret, load from environment variable or secret manager.".into(),
                    });
                }
            }
        }
    }
}

impl<'a, 'ast> Visit<'ast> for SecretVisitor<'a> {
    fn visit_expr_lit(&mut self, node: &'ast syn::ExprLit) {
        if let syn::Lit::Str(lit_str) = &node.lit {
            self.check_string_literal(&lit_str.value(), lit_str.span());
        }
        syn::visit::visit_expr_lit(self, node);
    }
}

/// Calculate Shannon entropy of a string.
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Truncate a secret for display, showing only the first 8 characters.
fn truncate_secret(s: &str) -> String {
    if s.len() <= 8 {
        format!("\"{}\"", s)
    } else {
        format!("\"{}...\"", &s[..8])
    }
}

/// Filter out common false positives for entropy check.
fn is_likely_false_positive(s: &str) -> bool {
    // URLs, file paths, SQL, HTML, and common format strings are not secrets
    s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with('/')
        || s.contains("SELECT ")
        || s.contains("INSERT ")
        || s.contains("UPDATE ")
        || s.contains("DELETE ")
        || s.starts_with('<')
        || s.contains("{}")
        || s.contains("{0}")
        || s.contains('\n')  // Multi-line strings are rarely secrets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = HardcodedSecrets::new();
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_aws_key() {
        let findings = check(r#"fn foo() { let k = "AKIAIOSFODNN7EXAMPLE"; }"#);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("AWS"));
    }

    #[test]
    fn detects_github_token() {
        let findings = check(r#"fn foo() { let t = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"; }"#);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("GitHub"));
    }

    #[test]
    fn detects_openai_key() {
        let findings = check(r#"fn foo() { let k = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"; }"#);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_normal_strings() {
        let findings = check(r#"fn foo() { let s = "hello world"; }"#);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_urls() {
        let findings = check(r#"fn foo() { let u = "https://example.com/api/v1/resource?key=value&other=thing"; }"#);
        assert!(findings.is_empty());
    }

    #[test]
    fn entropy_calculation() {
        // Low entropy - repeating characters
        assert!(shannon_entropy("aaaaaaaaaaaaaaaaaaaaa") < 1.0);
        // High entropy - random-looking
        assert!(shannon_entropy("aB3$xY9!mK7@pL2#nQ5&") > 4.0);
    }
}
