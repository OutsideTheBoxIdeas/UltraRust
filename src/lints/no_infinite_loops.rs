// Reject loop {} without provable break
// Catches infinite loops that have no break, return, or ? operator inside.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

pub struct NoInfiniteLoops;

impl AnalysisPass for NoInfiniteLoops {
    fn name(&self) -> &str {
        "no_infinite_loops"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = InfiniteLoopVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct InfiniteLoopVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for InfiniteLoopVisitor {
    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        // Check if the loop body contains a break, return, or ? at the current nesting level
        if !loop_body_has_exit(&node.body) {
            let span = node.loop_token.span;
            self.findings.push(Finding {
                source: "ultrarust".into(),
                check_name: "no_infinite_loops".into(),
                severity: Severity::High,
                file: self.path.clone(),
                line: span.start().line,
                col: span.start().column,
                message: "Unconditional `loop` without a reachable `break`, `return`, or `?` operator.".into(),
                snippet: "loop { ... }".into(),
                fix: "Add a `break` condition, use `while` with a condition, or add a `return` path.".into(),
            });
        }

        // Continue visiting nested expressions (but not nested loops - those are checked separately)
        syn::visit::visit_expr_loop(self, node);
    }
}

/// Checks whether a block contains at least one exit point (break, return, ?)
/// at the current loop nesting level (does not descend into nested loops/closures).
fn loop_body_has_exit(block: &syn::Block) -> bool {
    let mut checker = ExitChecker { found_exit: false };
    for stmt in &block.stmts {
        checker.visit_stmt(stmt);
        if checker.found_exit {
            return true;
        }
    }
    false
}

struct ExitChecker {
    found_exit: bool,
}

impl<'ast> Visit<'ast> for ExitChecker {
    fn visit_expr_break(&mut self, _node: &'ast syn::ExprBreak) {
        self.found_exit = true;
    }

    fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
        self.found_exit = true;
    }

    fn visit_expr_try(&mut self, _node: &'ast syn::ExprTry) {
        // The ? operator can exit the enclosing function on Err
        self.found_exit = true;
    }

    // Do NOT descend into nested loops - a break in a nested loop
    // does not break the outer loop.
    fn visit_expr_loop(&mut self, _node: &'ast syn::ExprLoop) {
        // intentionally do not recurse
    }

    fn visit_expr_while(&mut self, _node: &'ast syn::ExprWhile) {
        // intentionally do not recurse
    }

    fn visit_expr_for_loop(&mut self, _node: &'ast syn::ExprForLoop) {
        // intentionally do not recurse
    }

    // Do NOT descend into closures - a return in a closure
    // does not exit the enclosing function.
    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {
        // intentionally do not recurse
    }

    // Do NOT descend into async blocks
    fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {
        // intentionally do not recurse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = NoInfiniteLoops;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_loop_without_break() {
        let findings = check("fn foo() { loop { do_work(); } }");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_loop_with_break() {
        let findings = check("fn foo() { loop { if done() { break; } } }");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_loop_with_return() {
        let findings = check("fn foo() -> i32 { loop { return 42; } }");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_loop_with_question_mark() {
        let findings = check("fn foo() -> Result<(), Error> { loop { try_thing()?; } }");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_break_only_in_nested_loop() {
        // The break is for the inner loop, not the outer one
        let findings = check(
            "fn foo() { loop { for x in items { break; } } }"
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detects_return_only_in_closure() {
        let findings = check(
            "fn foo() { loop { let f = || { return 1; }; } }"
        );
        assert_eq!(findings.len(), 1);
    }
}
