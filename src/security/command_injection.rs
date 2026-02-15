// Detect unsanitized input in Command::new() args
// Simple intra-function taint analysis: tracks function parameters flowing into Command::arg().

use std::collections::HashSet;
use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

pub struct CommandInjection;

impl AnalysisPass for CommandInjection {
    fn name(&self) -> &str {
        "command_injection"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = CmdInjVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct CmdInjVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for CmdInjVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let tainted = collect_param_names(&node.sig);
        if !tainted.is_empty() {
            let mut checker = TaintChecker {
                tainted,
                findings: &mut self.findings,
                path: &self.path,
            };
            checker.visit_block(&node.block);
        }
        // Do NOT recurse into nested functions via default visit
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let tainted = collect_param_names(&node.sig);
        if !tainted.is_empty() {
            let mut checker = TaintChecker {
                tainted,
                findings: &mut self.findings,
                path: &self.path,
            };
            checker.visit_block(&node.block);
        }
    }
}

struct TaintChecker<'a> {
    tainted: HashSet<String>,
    findings: &'a mut Vec<Finding>,
    path: &'a Path,
}

impl<'a, 'ast> Visit<'ast> for TaintChecker<'a> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method_name = node.method.to_string();

        // Check for .arg(), .args(), .env() calls on Command-like expressions
        if method_name == "arg" || method_name == "args" || method_name == "env" {
            // Check if any argument to .arg() is tainted
            for arg_expr in &node.args {
                if expr_is_tainted(arg_expr, &self.tainted) {
                    let span = node.method.span();
                    self.findings.push(Finding {
                        source: "security".into(),
                        check_name: "command_injection".into(),
                        severity: Severity::Critical,
                        file: self.path.to_path_buf(),
                        line: span.start().line,
                        col: span.start().column,
                        message: format!(
                            "Potential command injection: function parameter flows into `.{}()` without validation.",
                            method_name
                        ),
                        snippet: format!(".{}(<tainted>)", method_name),
                        fix: "Validate and sanitize the input before passing to Command. Use an allowlist of permitted values.".into(),
                    });
                }
            }
        }

        // Continue visiting
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        // Track taint propagation through let bindings:
        // let x = tainted_param; => x is also tainted
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
            collect_pat_names(&pat_type.pat, &mut names);
        }
    }
    names
}

/// Recursively collect identifier names from a pattern.
fn collect_pat_names(pat: &syn::Pat, names: &mut HashSet<String>) {
    match pat {
        syn::Pat::Ident(ident) => {
            names.insert(ident.ident.to_string());
        }
        syn::Pat::Tuple(tuple) => {
            for elem in &tuple.elems {
                collect_pat_names(elem, names);
            }
        }
        syn::Pat::TupleStruct(ts) => {
            for elem in &ts.elems {
                collect_pat_names(elem, names);
            }
        }
        syn::Pat::Struct(s) => {
            for field in &s.fields {
                collect_pat_names(&field.pat, names);
            }
        }
        syn::Pat::Reference(r) => {
            collect_pat_names(&r.pat, names);
        }
        _ => {}
    }
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
            // format!(...) with tainted args, or function calls with tainted args
            call.args.iter().any(|a| expr_is_tainted(a, tainted))
        }
        syn::Expr::Macro(m) => {
            // Check if any token in the macro matches a tainted name
            let tokens = m.mac.tokens.to_string();
            tainted.iter().any(|t| tokens.contains(t))
        }
        syn::Expr::Block(b) => {
            // Last expression in block
            b.block.stmts.last().map_or(false, |stmt| {
                if let syn::Stmt::Expr(e, _) = stmt {
                    expr_is_tainted(e, tainted)
                } else {
                    false
                }
            })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = CommandInjection;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_direct_param_in_arg() {
        let findings = check(
            r#"
            fn run(user_input: &str) {
                Command::new("sh").arg(user_input).spawn();
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("command injection"));
    }

    #[test]
    fn detects_taint_through_let() {
        let findings = check(
            r#"
            fn run(cmd: &str) {
                let x = cmd;
                Command::new("sh").arg(x).spawn();
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_hardcoded_args() {
        let findings = check(
            r#"
            fn run() {
                Command::new("ls").arg("-la").spawn();
            }
            "#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_no_params() {
        let findings = check(
            r#"
            fn run() {
                let x = "safe";
                Command::new("echo").arg(x).spawn();
            }
            "#,
        );
        assert!(findings.is_empty());
    }
}
