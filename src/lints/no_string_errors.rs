// Ban Result<T, String> and Result<T, &str>
// AI-generated code frequently uses string errors instead of proper error types.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

pub struct NoStringErrors;

impl AnalysisPass for NoStringErrors {
    fn name(&self) -> &str {
        "no_string_errors"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = StringErrorVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct StringErrorVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl StringErrorVisitor {
    /// Check if a type is `Result<T, String>` or `Result<T, &str>`.
    fn check_result_type(&mut self, type_path: &syn::TypePath) {
        let segment = match type_path.path.segments.last() {
            Some(s) => s,
            None => return,
        };

        if segment.ident != "Result" {
            return;
        }

        // Extract the generic arguments of Result<T, E>
        let args = match &segment.arguments {
            syn::PathArguments::AngleBracketed(args) => args,
            _ => return,
        };

        // Result has 2 type arguments: T and E. We care about E (the second one).
        let type_args: Vec<_> = args
            .args
            .iter()
            .filter_map(|arg| match arg {
                syn::GenericArgument::Type(ty) => Some(ty),
                _ => None,
            })
            .collect();

        if type_args.len() < 2 {
            return;
        }

        let error_type = type_args[1];

        if is_string_type(error_type) || is_str_ref_type(error_type) {
            let span = segment.ident.span();
            let error_type_name = if is_string_type(error_type) {
                "String"
            } else {
                "&str"
            };
            self.findings.push(Finding {
                source: "ultrarusty".into(),
                check_name: "no_string_errors".into(),
                severity: Severity::Medium,
                file: self.path.clone(),
                line: span.start().line,
                col: span.start().column,
                message: format!(
                    "Use of `Result<T, {}>` is banned. Use a proper error type instead.",
                    error_type_name
                ),
                snippet: format!("Result<_, {}>", error_type_name),
                fix: "Define a custom error enum or use `anyhow::Error` / `thiserror::Error`.".into(),
            });
        }
    }
}

/// Check if a type is `String`.
fn is_string_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        if let Some(segment) = type_path.path.segments.last() {
            return segment.ident == "String";
        }
    }
    false
}

/// Check if a type is `&str`.
fn is_str_ref_type(ty: &syn::Type) -> bool {
    if let syn::Type::Reference(type_ref) = ty {
        if let syn::Type::Path(type_path) = type_ref.elem.as_ref() {
            if let Some(segment) = type_path.path.segments.last() {
                return segment.ident == "str";
            }
        }
    }
    false
}

impl<'ast> Visit<'ast> for StringErrorVisitor {
    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        self.check_result_type(node);
        syn::visit::visit_type_path(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = NoStringErrors;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_result_string() {
        let findings = check("fn foo() -> Result<i32, String> { Ok(0) }");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("String"));
    }

    #[test]
    fn detects_result_str_ref() {
        let findings = check("fn foo() -> Result<i32, &str> { Ok(0) }");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("&str"));
    }

    #[test]
    fn allows_proper_error_types() {
        let findings = check("fn foo() -> Result<i32, MyError> { Ok(0) }");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_result_without_generics() {
        let findings = check("type MyResult = Result<i32, std::io::Error>;");
        assert!(findings.is_empty());
    }
}
