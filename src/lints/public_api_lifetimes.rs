// Require explicit lifetimes on pub fn with references
// Elided lifetimes on public APIs hide the relationship between input and output borrows.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

pub struct PublicApiLifetimes;

impl AnalysisPass for PublicApiLifetimes {
    fn name(&self) -> &str {
        "public_api_lifetimes"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = LifetimeVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct LifetimeVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl LifetimeVisitor {
    fn check_fn_signature(
        &mut self,
        vis: &syn::Visibility,
        sig: &syn::Signature,
    ) {
        // Only check public functions
        if !matches!(vis, syn::Visibility::Public(_)) {
            return;
        }

        // Check if the function has reference parameters or reference return types
        let has_ref_in_inputs = sig.inputs.iter().any(|arg| match arg {
            syn::FnArg::Typed(pat_type) => type_contains_reference(&pat_type.ty),
            syn::FnArg::Receiver(receiver) => receiver.reference.is_some(),
        });

        let has_ref_in_output = match &sig.output {
            syn::ReturnType::Default => false,
            syn::ReturnType::Type(_, ty) => type_contains_reference(ty),
        };

        // If the function has references in both input and output, it needs explicit lifetimes
        if has_ref_in_inputs && has_ref_in_output {
            // Check if the function already has explicit lifetime parameters
            let has_lifetime_params = sig.generics.params.iter().any(|p| {
                matches!(p, syn::GenericParam::Lifetime(_))
            });

            if !has_lifetime_params {
                let span = sig.ident.span();
                self.findings.push(Finding {
                    source: "ultrarusty".into(),
                    check_name: "public_api_lifetimes".into(),
                    severity: Severity::Medium,
                    file: self.path.clone(),
                    line: span.start().line,
                    col: span.start().column,
                    message: format!(
                        "Public function `{}` has elided lifetimes. Add explicit lifetime parameters to clarify borrow relationships.",
                        sig.ident
                    ),
                    snippet: format!("pub fn {}(...) -> ...", sig.ident),
                    fix: "Add explicit lifetime parameters, e.g.: `pub fn foo<'a>(s: &'a str) -> &'a str`".into(),
                });
            }
        }
    }
}

/// Returns true if a type contains any references (including nested ones).
fn type_contains_reference(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(_) => true,
        syn::Type::Path(type_path) => {
            // Check generic arguments like Option<&str>, Vec<&str>
            if let Some(segment) = type_path.path.segments.last() {
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    return args.args.iter().any(|arg| {
                        if let syn::GenericArgument::Type(inner_ty) = arg {
                            type_contains_reference(inner_ty)
                        } else {
                            false
                        }
                    });
                }
            }
            false
        }
        syn::Type::Tuple(tuple) => tuple.elems.iter().any(type_contains_reference),
        syn::Type::Slice(slice) => type_contains_reference(&slice.elem),
        syn::Type::Array(array) => type_contains_reference(&array.elem),
        syn::Type::Paren(paren) => type_contains_reference(&paren.elem),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for LifetimeVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.check_fn_signature(&node.vis, &node.sig);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.check_fn_signature(&node.vis, &node.sig);
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        // Trait methods are always public API if the trait is pub
        // For simplicity, we check all trait methods
        self.check_fn_signature(&syn::Visibility::Public(syn::token::Pub::default()), &node.sig);
        syn::visit::visit_trait_item_fn(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = PublicApiLifetimes;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_elided_lifetimes() {
        let findings = check("pub fn first(s: &str) -> &str { s }");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("elided lifetimes"));
    }

    #[test]
    fn allows_explicit_lifetimes() {
        let findings = check("pub fn first<'a>(s: &'a str) -> &'a str { s }");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_no_reference_output() {
        let findings = check("pub fn len(s: &str) -> usize { s.len() }");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_private_functions() {
        let findings = check("fn first(s: &str) -> &str { s }");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_nested_reference_in_return() {
        let findings = check("pub fn get(items: &[&str]) -> Option<&str> { None }");
        assert_eq!(findings.len(), 1);
    }
}
