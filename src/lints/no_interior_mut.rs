// Ban RefCell<T>, Cell<T>, UnsafeCell<T>
// These types bypass Rust's borrow checking at runtime, introducing potential panics.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

/// Banned interior mutability type names.
const BANNED_TYPES: &[&str] = &["RefCell", "Cell", "UnsafeCell"];

pub struct NoInteriorMutability;

impl AnalysisPass for NoInteriorMutability {
    fn name(&self) -> &str {
        "no_interior_mutability"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = InteriorMutVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct InteriorMutVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl InteriorMutVisitor {
    fn check_type_path(&mut self, type_path: &syn::TypePath) {
        // Check the last segment of the path (e.g. std::cell::RefCell -> RefCell)
        if let Some(segment) = type_path.path.segments.last() {
            let ident = segment.ident.to_string();
            if BANNED_TYPES.contains(&ident.as_str()) {
                let span = segment.ident.span();
                self.findings.push(Finding {
                    source: "ultrarusty".into(),
                    check_name: "no_interior_mutability".into(),
                    severity: Severity::High,
                    file: self.path.clone(),
                    line: span.start().line,
                    col: span.start().column,
                    message: format!(
                        "Use of `{}` is banned. Interior mutability bypasses borrow checking at compile time.",
                        ident
                    ),
                    snippet: ident.clone(),
                    fix: format!(
                        "Refactor to avoid `{}`. Use proper ownership, or pass `&mut` references explicitly.",
                        ident
                    ),
                });
            }
        }
    }
}

impl<'ast> Visit<'ast> for InteriorMutVisitor {
    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        self.check_type_path(node);
        // Continue visiting nested types (e.g. Arc<RefCell<T>>)
        syn::visit::visit_type_path(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = NoInteriorMutability;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_refcell() {
        let findings = check("use std::cell::RefCell; fn foo() { let _x: RefCell<i32> = RefCell::new(0); }");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.message.contains("RefCell")));
    }

    #[test]
    fn detects_cell() {
        let findings = check("fn foo() { let _x: std::cell::Cell<bool> = std::cell::Cell::new(false); }");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.message.contains("Cell")));
    }

    #[test]
    fn detects_unsafecell() {
        let findings = check("use std::cell::UnsafeCell; struct Foo { inner: UnsafeCell<u8> }");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.message.contains("UnsafeCell")));
    }

    #[test]
    fn allows_normal_types() {
        let findings = check("fn foo() -> String { String::new() }");
        assert!(findings.is_empty());
    }
}
