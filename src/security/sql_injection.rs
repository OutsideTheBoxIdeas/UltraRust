// Detect format strings flowing into SQL query methods
// Flags format!() or string concatenation used in calls to query/execute/sql methods.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

/// Method names that typically execute SQL.
const SQL_METHODS: &[&str] = &[
    "query",
    "execute",
    "query_one",
    "query_opt",
    "query_as",
    "query_scalar",
    "raw_query",
    "raw_execute",
    "sql",
    "prepare",
];

pub struct SqlInjection;

impl AnalysisPass for SqlInjection {
    fn name(&self) -> &str {
        "sql_injection"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = SqlVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct SqlVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for SqlVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method_name = node.method.to_string();

        if SQL_METHODS.contains(&method_name.as_str()) {
            // Check if any argument is a format!() macro or string concatenation
            for arg in &node.args {
                if is_format_or_concat(arg) {
                    let span = node.method.span();
                    self.findings.push(Finding {
                        source: "security".into(),
                        check_name: "sql_injection".into(),
                        severity: Severity::Critical,
                        file: self.path.clone(),
                        line: span.start().line,
                        col: span.start().column,
                        message: format!(
                            "Potential SQL injection: format string or concatenation used in `.{}()` call.",
                            method_name
                        ),
                        snippet: format!(".{}(format!(...))", method_name),
                        fix: "Use parameterized queries with `$1`, `?`, or `:name` placeholders instead of string formatting.".into(),
                    });
                }
            }
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        // Check for function calls like sqlx::query(format!(...))
        if let syn::Expr::Path(path_expr) = node.func.as_ref() {
            if let Some(last_seg) = path_expr.path.segments.last() {
                let name = last_seg.ident.to_string();
                if SQL_METHODS.contains(&name.as_str()) {
                    for arg in &node.args {
                        if is_format_or_concat(arg) {
                            let span = last_seg.ident.span();
                            self.findings.push(Finding {
                                source: "security".into(),
                                check_name: "sql_injection".into(),
                                severity: Severity::Critical,
                                file: self.path.clone(),
                                line: span.start().line,
                                col: span.start().column,
                                message: format!(
                                    "Potential SQL injection: format string or concatenation in `{}()` call.",
                                    name
                                ),
                                snippet: format!("{}(format!(...))", name),
                                fix: "Use parameterized queries with `$1`, `?`, or `:name` placeholders.".into(),
                            });
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// Check if an expression is a format!() macro call or string concatenation.
fn is_format_or_concat(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Macro(m) => {
            // Check for format!(), format_args!()
            if let Some(last_seg) = m.mac.path.segments.last() {
                let name = last_seg.ident.to_string();
                return name == "format" || name == "format_args";
            }
            false
        }
        // Check for "..." + variable (binary add on strings)
        syn::Expr::Binary(bin) => {
            matches!(bin.op, syn::BinOp::Add(_) | syn::BinOp::AddAssign(_))
        }
        // Check for reference to a format expression
        syn::Expr::Reference(r) => is_format_or_concat(&r.expr),
        syn::Expr::Paren(p) => is_format_or_concat(&p.expr),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = SqlInjection;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_format_in_query() {
        let findings = check(
            r#"
            fn get_user(db: &Pool, name: &str) {
                db.query(&format!("SELECT * FROM users WHERE name = '{}'", name));
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("SQL injection"));
    }

    #[test]
    fn detects_format_in_execute() {
        let findings = check(
            r#"
            fn delete_user(conn: &Connection, id: i64) {
                conn.execute(format!("DELETE FROM users WHERE id = {}", id));
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_parameterized_queries() {
        let findings = check(
            r#"
            fn get_user(db: &Pool, name: &str) {
                db.query("SELECT * FROM users WHERE name = $1");
            }
            "#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_string_concat_in_query() {
        let findings = check(
            r#"
            fn search(db: &Pool, term: &str) {
                db.query("SELECT * FROM items WHERE name = '" + term + "'");
            }
            "#,
        );
        assert_eq!(findings.len(), 1);
    }
}
