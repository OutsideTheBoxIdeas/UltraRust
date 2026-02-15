// Detect thread_rng() in security contexts
// thread_rng() is not suitable for cryptographic purposes. Flag when used near
// security-related identifiers (token, key, secret, password, salt, nonce, iv).

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

/// Identifiers that indicate a security context.
const SECURITY_IDENTS: &[&str] = &[
    "token", "key", "secret", "password", "passwd", "pwd",
    "salt", "nonce", "iv", "seed", "auth", "credential",
    "cipher", "crypto", "encrypt", "decrypt", "sign", "verify",
    "otp", "totp", "hotp", "session_id", "csrf", "api_key",
];

/// Names of insecure random functions/types.
const INSECURE_RNG_NAMES: &[&str] = &[
    "thread_rng",
    "SmallRng",
    "StdRng",
];

pub struct InsecureRandom;

impl AnalysisPass for InsecureRandom {
    fn name(&self) -> &str {
        "insecure_random"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = RandomVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct RandomVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for RandomVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let fn_name = node.sig.ident.to_string().to_lowercase();
        let is_security_context = SECURITY_IDENTS.iter().any(|s| fn_name.contains(s));

        if is_security_context {
            let mut checker = RngUsageChecker {
                findings: &mut self.findings,
                path: &self.path,
                fn_name: &node.sig.ident.to_string(),
            };
            checker.visit_block(&node.block);
        }

        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let fn_name = node.sig.ident.to_string().to_lowercase();
        let is_security_context = SECURITY_IDENTS.iter().any(|s| fn_name.contains(s));

        if is_security_context {
            let mut checker = RngUsageChecker {
                findings: &mut self.findings,
                path: &self.path,
                fn_name: &node.sig.ident.to_string(),
            };
            checker.visit_block(&node.block);
        }

        syn::visit::visit_impl_item_fn(self, node);
    }
}

struct RngUsageChecker<'a> {
    findings: &'a mut Vec<Finding>,
    path: &'a Path,
    fn_name: &'a str,
}

impl<'a, 'ast> Visit<'ast> for RngUsageChecker<'a> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path_expr) = node.func.as_ref() {
            if let Some(last_seg) = path_expr.path.segments.last() {
                let name = last_seg.ident.to_string();
                if INSECURE_RNG_NAMES.contains(&name.as_str()) {
                    let span = last_seg.ident.span();
                    self.findings.push(Finding {
                        source: "security".into(),
                        check_name: "insecure_random".into(),
                        severity: Severity::High,
                        file: self.path.to_path_buf(),
                        line: span.start().line,
                        col: span.start().column,
                        message: format!(
                            "Insecure RNG `{}()` used in security-sensitive function `{}`. Use `OsRng` or `rand::rngs::OsRng` for cryptographic purposes.",
                            name, self.fn_name
                        ),
                        snippet: format!("{}()", name),
                        fix: "Use `rand::rngs::OsRng` or `getrandom` for security-sensitive randomness.".into(),
                    });
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if let Some(last_seg) = node.path.segments.last() {
            let name = last_seg.ident.to_string();
            if INSECURE_RNG_NAMES.contains(&name.as_str()) {
                let span = last_seg.ident.span();
                self.findings.push(Finding {
                    source: "security".into(),
                    check_name: "insecure_random".into(),
                    severity: Severity::High,
                    file: self.path.to_path_buf(),
                    line: span.start().line,
                    col: span.start().column,
                    message: format!(
                        "Insecure RNG `{}` used in security-sensitive function `{}`. Use `OsRng` for cryptographic purposes.",
                        name, self.fn_name
                    ),
                    snippet: name,
                    fix: "Use `rand::rngs::OsRng` or `getrandom` for security-sensitive randomness.".into(),
                });
            }
        }
        syn::visit::visit_expr_path(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = InsecureRandom;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_thread_rng_in_token_generation() {
        let findings = check(
            r#"
            fn generate_token() -> u64 {
                let mut rng = thread_rng();
                rng.gen()
            }
            "#,
        );
        assert!(!findings.is_empty());
        assert!(findings[0].message.contains("thread_rng"));
    }

    #[test]
    fn detects_thread_rng_in_password_function() {
        let findings = check(
            r#"
            fn generate_password(length: usize) -> String {
                let rng = rand::thread_rng();
                "placeholder".to_string()
            }
            "#,
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn allows_thread_rng_in_non_security_context() {
        let findings = check(
            r#"
            fn shuffle_items(items: &mut Vec<i32>) {
                let mut rng = thread_rng();
                items.shuffle(&mut rng);
            }
            "#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_os_rng_in_security_context() {
        let findings = check(
            r#"
            fn generate_token() -> u64 {
                let mut rng = OsRng;
                rng.gen()
            }
            "#,
        );
        assert!(findings.is_empty());
    }
}
