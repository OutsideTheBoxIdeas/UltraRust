// Reject >4 generic type parameters
// Too many type parameters indicate over-abstraction and hurt readability.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

const MAX_TYPE_PARAMS: usize = 4;

pub struct BoundedGenerics;

impl AnalysisPass for BoundedGenerics {
    fn name(&self) -> &str {
        "bounded_generics"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = GenericVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct GenericVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl GenericVisitor {
    fn check_generics(&mut self, name: &str, generics: &syn::Generics, span: proc_macro2::Span) {
        let type_param_count = generics
            .params
            .iter()
            .filter(|p| matches!(p, syn::GenericParam::Type(_)))
            .count();

        if type_param_count > MAX_TYPE_PARAMS {
            self.findings.push(Finding {
                source: "ultrarusty".into(),
                check_name: "bounded_generics".into(),
                severity: Severity::Medium,
                file: self.path.clone(),
                line: span.start().line,
                col: span.start().column,
                message: format!(
                    "`{}` has {} type parameters (max {}). Reduce generic complexity.",
                    name, type_param_count, MAX_TYPE_PARAMS
                ),
                snippet: format!("{}<{} type params>", name, type_param_count),
                fix: format!(
                    "Reduce to at most {} type parameters. Consider using trait objects, \
                     associated types, or breaking into smaller abstractions.",
                    MAX_TYPE_PARAMS
                ),
            });
        }
    }
}

impl<'ast> Visit<'ast> for GenericVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.check_generics(
            &node.sig.ident.to_string(),
            &node.sig.generics,
            node.sig.ident.span(),
        );
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.check_generics(
            &node.ident.to_string(),
            &node.generics,
            node.ident.span(),
        );
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        self.check_generics(
            &node.ident.to_string(),
            &node.generics,
            node.ident.span(),
        );
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        self.check_generics(
            &node.ident.to_string(),
            &node.generics,
            node.ident.span(),
        );
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let name = if let Some((_, path, _)) = &node.trait_ {
            path.segments
                .last()
                .map_or("impl".into(), |s| format!("impl {}", s.ident))
        } else {
            "impl".into()
        };
        self.check_generics(&name, &node.generics, node.impl_token.span);
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.check_generics(
            &node.sig.ident.to_string(),
            &node.sig.generics,
            node.sig.ident.span(),
        );
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.check_generics(
            &node.sig.ident.to_string(),
            &node.sig.generics,
            node.sig.ident.span(),
        );
        syn::visit::visit_trait_item_fn(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = BoundedGenerics;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn allows_four_type_params() {
        let findings = check("fn foo<A, B, C, D>(a: A, b: B, c: C, d: D) {}");
        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_five_type_params() {
        let findings = check("fn foo<A, B, C, D, E>(a: A, b: B, c: C, d: D, e: E) {}");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("5 type parameters"));
    }

    #[test]
    fn rejects_six_type_params_on_struct() {
        let findings = check("struct Foo<A, B, C, D, E, F> { a: A, b: B, c: C, d: D, e: E, f: F }");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn lifetime_params_not_counted() {
        // Lifetimes are not type parameters
        let findings = check("fn foo<'a, 'b, A, B, C, D>(a: &'a A, b: &'b B, c: C, d: D) {}");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_no_generics() {
        let findings = check("fn foo(x: i32) -> i32 { x }");
        assert!(findings.is_empty());
    }
}
