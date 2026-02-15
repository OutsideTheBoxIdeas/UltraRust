// Detect non-constant-time comparison on secrets
// Flags == and != operators on variables named token, secret, key, hash, password, etc.

use std::path::Path;

use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

/// Variable name substrings that indicate secret data.
const SECRET_VAR_NAMES: &[&str] = &[
    "token", "secret", "key", "hash", "password", "passwd", "pwd",
    "digest", "signature", "hmac", "mac", "auth", "credential",
    "api_key", "apikey", "access_key", "session",
];

pub struct TimingAttack;

impl AnalysisPass for TimingAttack {
    fn name(&self) -> &str {
        "timing_attack"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = TimingVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct TimingVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for TimingVisitor {
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        // Only check == and != comparisons
        if matches!(node.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            let left_name = extract_var_name(&node.left);
            let right_name = extract_var_name(&node.right);

            let secret_side = [left_name.as_deref(), right_name.as_deref()]
                .iter()
                .filter_map(|n| *n)
                .find(|name| {
                    let lower = name.to_lowercase();
                    SECRET_VAR_NAMES.iter().any(|s| lower.contains(s))
                });

            if let Some(name) = secret_side {
                let span = node.op.span();
                let op_str = if matches!(node.op, syn::BinOp::Eq(_)) {
                    "=="
                } else {
                    "!="
                };
                self.findings.push(Finding {
                    source: "security".into(),
                    check_name: "timing_attack".into(),
                    severity: Severity::High,
                    file: self.path.clone(),
                    line: span.start().line,
                    col: span.start().column,
                    message: format!(
                        "Non-constant-time comparison (`{}`) on secret-like variable `{}`. Vulnerable to timing attacks.",
                        op_str, name
                    ),
                    snippet: format!("{} {} ...", name, op_str),
                    fix: "Use `constant_time_eq` or `subtle::ConstantTimeEq` for comparing secrets.".into(),
                });
            }
        }

        syn::visit::visit_expr_binary(self, node);
    }
}

/// Try to extract a variable name from an expression.
fn extract_var_name(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => {
            path.path.get_ident().map(|i| i.to_string())
        }
        syn::Expr::Field(field) => {
            if let syn::Member::Named(ident) = &field.member {
                Some(ident.to_string())
            } else {
                None
            }
        }
        syn::Expr::Reference(r) => extract_var_name(&r.expr),
        syn::Expr::Paren(p) => extract_var_name(&p.expr),
        syn::Expr::MethodCall(mc) => {
            // For things like self.token
            Some(mc.method.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = TimingAttack;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_token_comparison() {
        let findings = check(
            r#"
            fn verify(provided_token: &str, stored_token: &str) -> bool {
                provided_token == stored_token
            }
            "#,
        );
        assert!(!findings.is_empty());
        assert!(findings[0].message.contains("timing"));
    }

    #[test]
    fn detects_password_comparison() {
        let findings = check(
            r#"
            fn check_password(password: &str, expected: &str) -> bool {
                password == expected
            }
            "#,
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn detects_hash_comparison() {
        let findings = check(
            r#"
            fn verify_hash(computed_hash: &[u8], expected: &[u8]) -> bool {
                computed_hash == expected
            }
            "#,
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn allows_non_secret_comparison() {
        let findings = check(
            r#"
            fn check(count: i32, expected: i32) -> bool {
                count == expected
            }
            "#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_field_access_comparison() {
        let findings = check(
            r#"
            fn verify(request: &Request) -> bool {
                request.api_key == "expected"
            }
            "#,
        );
        assert!(!findings.is_empty());
    }
}
