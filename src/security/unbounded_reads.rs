// Detect read_to_string/read_to_end without size limits
// These methods read unbounded data into memory, which can cause OOM on untrusted input.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

/// Methods that read unbounded data into memory.
const UNBOUNDED_READ_METHODS: &[&str] = &[
    "read_to_string",
    "read_to_end",
];

pub struct UnboundedReads;

impl AnalysisPass for UnboundedReads {
    fn name(&self) -> &str {
        "unbounded_reads"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = ReadVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct ReadVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for ReadVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method_name = node.method.to_string();

        if UNBOUNDED_READ_METHODS.contains(&method_name.as_str()) {
            let span = node.method.span();
            self.findings.push(Finding {
                source: "security".into(),
                check_name: "unbounded_reads".into(),
                severity: Severity::High,
                file: self.path.clone(),
                line: span.start().line,
                col: span.start().column,
                message: format!(
                    "Unbounded `{}()` call. This reads unlimited data into memory.",
                    method_name
                ),
                snippet: format!(".{}()", method_name),
                fix: "Use `.take(MAX_SIZE)` before reading, or use a bounded reader to limit input size.".into(),
            });
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        // Check for std::fs::read_to_string() function call
        if let syn::Expr::Path(path_expr) = node.func.as_ref() {
            let segments: Vec<_> = path_expr
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let full_path = segments.join("::");

            if full_path.ends_with("read_to_string") || full_path == "read_to_string" {
                let span = path_expr
                    .path
                    .segments
                    .last()
                    .map_or(proc_macro2::Span::call_site(), |s| s.ident.span());

                self.findings.push(Finding {
                    source: "security".into(),
                    check_name: "unbounded_reads".into(),
                    severity: Severity::High,
                    file: self.path.clone(),
                    line: span.start().line,
                    col: span.start().column,
                    message: "Unbounded `read_to_string()` call. This reads the entire file into memory.".into(),
                    snippet: full_path,
                    fix: "Check file size before reading, or use a bounded reader.".into(),
                });
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = UnboundedReads;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_read_to_string_method() {
        let findings = check(
            r#"
            fn read(stream: &mut TcpStream) {
                let mut buf = String::new();
                stream.read_to_string(&mut buf);
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("read_to_string"));
    }

    #[test]
    fn detects_read_to_end_method() {
        let findings = check(
            r#"
            fn read(stream: &mut TcpStream) {
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf);
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("read_to_end"));
    }

    #[test]
    fn detects_fs_read_to_string() {
        let findings = check(
            r#"
            fn load(path: &Path) {
                let content = std::fs::read_to_string(path);
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_other_methods() {
        let findings = check(
            r#"
            fn read(stream: &mut TcpStream) {
                let mut buf = [0u8; 1024];
                stream.read(&mut buf);
            }
            "#,
        );
        assert!(findings.is_empty());
    }
}
