// Detect unbounded deserialization
// Flags deserialization from untrusted sources (network/file) without size limits.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

/// Deserialization function names that are potentially dangerous.
const DESER_FUNCTIONS: &[&str] = &[
    "from_str",
    "from_slice",
    "from_reader",
    "from_bytes",
    "from_value",
    "deserialize",
];

/// Crate/module prefixes associated with deserialization.
const DESER_PREFIXES: &[&str] = &[
    "serde_json",
    "serde_yaml",
    "serde_cbor",
    "bincode",
    "rmp_serde",
    "toml",
    "ciborium",
    "postcard",
];

pub struct InsecureDeserialization;

impl AnalysisPass for InsecureDeserialization {
    fn name(&self) -> &str {
        "insecure_deserialization"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = DeserVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct DeserVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for DeserVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        // Check for calls like serde_json::from_str(), serde_json::from_reader()
        if let syn::Expr::Path(path_expr) = node.func.as_ref() {
            let segments: Vec<_> = path_expr
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();

            let full_path = segments.join("::");

            // Check if it's a known deserialization function from a known crate
            let is_deser_call = DESER_PREFIXES.iter().any(|prefix| {
                full_path.starts_with(prefix)
            }) && segments.last().map_or(false, |last| {
                DESER_FUNCTIONS.contains(&last.as_str())
            });

            if is_deser_call {
                // Check specifically for from_reader, from_slice, from_bytes
                // (from_str with a bounded &str is less dangerous than from_reader)
                let last_segment = segments.last().map(|s| s.as_str()).unwrap_or("");
                let severity = if last_segment == "from_reader" {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let span = path_expr.path.segments.last().map_or(
                    proc_macro2::Span::call_site(),
                    |s| s.ident.span(),
                );

                self.findings.push(Finding {
                    source: "security".into(),
                    check_name: "insecure_deserialization".into(),
                    severity,
                    file: self.path.clone(),
                    line: span.start().line,
                    col: span.start().column,
                    message: format!(
                        "Unbounded deserialization via `{}`. Input size is not validated.",
                        full_path
                    ),
                    snippet: full_path,
                    fix: "Limit input size before deserialization. Use `take()` on readers or validate string length.".into(),
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
        let pass = InsecureDeserialization;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_serde_json_from_str() {
        let findings = check(
            r#"
            fn parse(data: &str) {
                let val: Value = serde_json::from_str(data).unwrap();
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("serde_json::from_str"));
    }

    #[test]
    fn detects_serde_json_from_reader() {
        let findings = check(
            r#"
            fn parse(reader: impl Read) {
                let val: Value = serde_json::from_reader(reader).unwrap();
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn detects_bincode_deserialize() {
        let findings = check(
            r#"
            fn parse(data: &[u8]) {
                let val: Data = bincode::deserialize(data).unwrap();
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_non_deser_calls() {
        let findings = check(
            r#"
            fn foo() {
                let x = serde_json::to_string(&data).unwrap();
            }
            "#,
        );
        assert!(findings.is_empty());
    }
}
