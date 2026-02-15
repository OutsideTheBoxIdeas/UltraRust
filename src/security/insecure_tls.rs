// Detect disabled certificate validation
// Flags danger_accept_invalid_certs(true), danger_accept_invalid_hostnames(true),
// and similar TLS security bypasses.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

/// Methods that disable TLS security when called with `true`.
const DANGER_METHODS: &[&str] = &[
    "danger_accept_invalid_certs",
    "danger_accept_invalid_hostnames",
    "set_verify",
    "accept_invalid_certs",
    "accept_invalid_hostnames",
];

pub struct InsecureTls;

impl AnalysisPass for InsecureTls {
    fn name(&self) -> &str {
        "insecure_tls"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = TlsVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct TlsVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for TlsVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method_name = node.method.to_string();

        if DANGER_METHODS.contains(&method_name.as_str()) {
            // Check if the argument is `true` (disabling verification)
            let is_disabling = node.args.first().map_or(false, |arg| {
                if let syn::Expr::Lit(lit) = arg {
                    if let syn::Lit::Bool(b) = &lit.lit {
                        return b.value;
                    }
                }
                // For set_verify, any call is suspicious
                method_name == "set_verify"
            });

            if is_disabling || method_name == "set_verify" {
                let span = node.method.span();
                self.findings.push(Finding {
                    source: "security".into(),
                    check_name: "insecure_tls".into(),
                    severity: Severity::Critical,
                    file: self.path.clone(),
                    line: span.start().line,
                    col: span.start().column,
                    message: format!(
                        "TLS certificate validation disabled via `.{}()`. This allows MITM attacks.",
                        method_name
                    ),
                    snippet: format!(".{}(true)", method_name),
                    fix: "Do not disable certificate validation. Use proper CA certificates for testing.".into(),
                });
            }
        }

        syn::visit::visit_expr_method_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = InsecureTls;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_danger_accept_invalid_certs() {
        let findings = check(
            r#"
            fn make_client() {
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build();
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("certificate validation disabled"));
    }

    #[test]
    fn detects_danger_accept_invalid_hostnames() {
        let findings = check(
            r#"
            fn make_client() {
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_hostnames(true)
                    .build();
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_danger_accept_invalid_certs_false() {
        let findings = check(
            r#"
            fn make_client() {
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(false)
                    .build();
            }
            "#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_normal_builder() {
        let findings = check(
            r#"
            fn make_client() {
                let client = reqwest::Client::builder().build();
            }
            "#,
        );
        assert!(findings.is_empty());
    }
}
