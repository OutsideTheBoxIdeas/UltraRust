// Detect unsanitized input in file paths
// Simple intra-function taint analysis: tracks function parameters flowing into Path::join() or PathBuf::push().

use std::collections::HashSet;
use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

pub struct PathTraversal;

impl AnalysisPass for PathTraversal {
    fn name(&self) -> &str {
        "path_traversal"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = PathTravVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct PathTravVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

/// Dangerous path methods that can lead to path traversal.
const DANGEROUS_PATH_METHODS: &[&str] = &["join", "push"];

impl<'ast> Visit<'ast> for PathTravVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let tainted = collect_param_names(&node.sig);
        if !tainted.is_empty() {
            let mut checker = PathTaintChecker {
                tainted,
                findings: &mut self.findings,
                path: &self.path,
            };
            checker.visit_block(&node.block);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let tainted = collect_param_names(&node.sig);
        if !tainted.is_empty() {
            let mut checker = PathTaintChecker {
                tainted,
                findings: &mut self.findings,
                path: &self.path,
            };
            checker.visit_block(&node.block);
        }
    }
}

struct PathTaintChecker<'a> {
    tainted: HashSet<String>,
    findings: &'a mut Vec<Finding>,
    path: &'a Path,
}

impl<'a, 'ast> Visit<'ast> for PathTaintChecker<'a> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method_name = node.method.to_string();

        if DANGEROUS_PATH_METHODS.contains(&method_name.as_str()) {
            for arg_expr in &node.args {
                if expr_is_tainted(arg_expr, &self.tainted) {
                    let span = node.method.span();
                    self.findings.push(Finding {
                        source: "security".into(),
                        check_name: "path_traversal".into(),
                        severity: Severity::Critical,
                        file: self.path.to_path_buf(),
                        line: span.start().line,
                        col: span.start().column,
                        message: format!(
                            "Potential path traversal: function parameter flows into `.{}()` without validation.",
                            method_name
                        ),
                        snippet: format!(".{}(<tainted>)", method_name),
                        fix: "Validate the path component: reject `..`, absolute paths, and symlinks. Use a canonical path check.".into(),
                    });
                }
            }
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(init) = &node.init {
            if expr_is_tainted(&init.expr, &self.tainted) {
                if let syn::Pat::Ident(pat_ident) = &node.pat {
                    self.tainted.insert(pat_ident.ident.to_string());
                }
            }
        }
        syn::visit::visit_local(self, node);
    }
}

/// Collect all parameter names from a function signature.
fn collect_param_names(sig: &syn::Signature) -> HashSet<String> {
    let mut names = HashSet::new();
    for input in &sig.inputs {
        if let syn::FnArg::Typed(pat_type) = input {
            if let syn::Pat::Ident(ident) = pat_type.pat.as_ref() {
                names.insert(ident.ident.to_string());
            }
        }
    }
    names
}

/// Check if an expression references any tainted variable.
fn expr_is_tainted(expr: &syn::Expr, tainted: &HashSet<String>) -> bool {
    match expr {
        syn::Expr::Path(path) => {
            if let Some(ident) = path.path.get_ident() {
                return tainted.contains(&ident.to_string());
            }
            false
        }
        syn::Expr::Reference(r) => expr_is_tainted(&r.expr, tainted),
        syn::Expr::Paren(p) => expr_is_tainted(&p.expr, tainted),
        syn::Expr::Field(f) => expr_is_tainted(&f.base, tainted),
        syn::Expr::MethodCall(mc) => expr_is_tainted(&mc.receiver, tainted),
        syn::Expr::Call(call) => {
            call.args.iter().any(|a| expr_is_tainted(a, tainted))
        }
        syn::Expr::Macro(m) => {
            let tokens = m.mac.tokens.to_string();
            tainted.iter().any(|t| tokens.contains(t))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = PathTraversal;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_join_with_user_input() {
        let findings = check(
            r#"
            fn read_file(user_path: &str) {
                let full = Path::new("/data").join(user_path);
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("path traversal"));
    }

    #[test]
    fn detects_push_with_user_input() {
        let findings = check(
            r#"
            fn write_file(filename: &str) {
                let mut path = PathBuf::from("/uploads");
                path.push(filename);
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_hardcoded_paths() {
        let findings = check(
            r#"
            fn read_config() {
                let path = Path::new("/etc").join("config.toml");
            }
            "#,
        );
        assert!(findings.is_empty());
    }
}
