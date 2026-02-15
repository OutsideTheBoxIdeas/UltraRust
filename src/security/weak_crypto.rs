// Detect weak cryptographic algorithm usage
// Bans MD5, SHA1, DES, RC4, ECB mode, and other known-weak algorithms.

use std::path::Path;

use syn::visit::Visit;

use crate::driver::{AnalysisPass, Finding, Severity};

/// Banned cryptographic identifiers: (identifier, description, severity)
const BANNED_CRYPTO: &[(&str, &str, &str)] = &[
    // Hash functions
    ("Md5", "MD5 is cryptographically broken", "Use SHA-256 or SHA-3 instead"),
    ("MD5", "MD5 is cryptographically broken", "Use SHA-256 or SHA-3 instead"),
    ("md5", "MD5 is cryptographically broken", "Use SHA-256 or SHA-3 instead"),
    ("Sha1", "SHA-1 is cryptographically broken", "Use SHA-256 or SHA-3 instead"),
    ("SHA1", "SHA-1 is cryptographically broken", "Use SHA-256 or SHA-3 instead"),
    ("sha1", "SHA-1 is cryptographically broken", "Use SHA-256 or SHA-3 instead"),
    // Block ciphers
    ("Des", "DES has a 56-bit key and is broken", "Use AES-256 instead"),
    ("DES", "DES has a 56-bit key and is broken", "Use AES-256 instead"),
    ("des", "DES has a 56-bit key and is broken", "Use AES-256 instead"),
    ("TripleDes", "3DES is deprecated", "Use AES-256 instead"),
    ("Rc4", "RC4 has known biases and is broken", "Use AES-GCM or ChaCha20-Poly1305 instead"),
    ("RC4", "RC4 has known biases and is broken", "Use AES-GCM or ChaCha20-Poly1305 instead"),
    ("rc4", "RC4 has known biases and is broken", "Use AES-GCM or ChaCha20-Poly1305 instead"),
    ("Rc2", "RC2 is obsolete", "Use AES-256 instead"),
    // ECB mode
    ("Ecb", "ECB mode does not provide semantic security", "Use CBC, CTR, or GCM mode instead"),
    ("ECB", "ECB mode does not provide semantic security", "Use CBC, CTR, or GCM mode instead"),
    // Blowfish (small block size)
    ("Blowfish", "Blowfish has a 64-bit block size, vulnerable to birthday attacks", "Use AES-256 instead"),
];

pub struct WeakCrypto;

impl AnalysisPass for WeakCrypto {
    fn name(&self) -> &str {
        "weak_crypto"
    }

    fn check_file(&self, file: &syn::File, path: &Path) -> Vec<Finding> {
        let mut visitor = CryptoVisitor {
            findings: Vec::new(),
            path: path.to_path_buf(),
        };
        visitor.visit_file(file);
        visitor.findings
    }
}

struct CryptoVisitor {
    findings: Vec<Finding>,
    path: std::path::PathBuf,
}

impl<'ast> Visit<'ast> for CryptoVisitor {
    fn visit_path(&mut self, node: &'ast syn::Path) {
        // Check each segment of the path for banned crypto identifiers
        for segment in &node.segments {
            let ident = segment.ident.to_string();
            for &(banned, reason, fix) in BANNED_CRYPTO {
                if ident == banned {
                    let span = segment.ident.span();
                    self.findings.push(Finding {
                        source: "security".into(),
                        check_name: "weak_crypto".into(),
                        severity: Severity::High,
                        file: self.path.clone(),
                        line: span.start().line,
                        col: span.start().column,
                        message: format!("Weak cryptographic algorithm: {}.", reason),
                        snippet: ident.clone(),
                        fix: fix.into(),
                    });
                    break;
                }
            }
        }
        syn::visit::visit_path(self, node);
    }

    fn visit_use_path(&mut self, node: &'ast syn::UsePath) {
        let ident = node.ident.to_string();
        for &(banned, reason, fix) in BANNED_CRYPTO {
            if ident == banned {
                let span = node.ident.span();
                self.findings.push(Finding {
                    source: "security".into(),
                    check_name: "weak_crypto".into(),
                    severity: Severity::High,
                    file: self.path.clone(),
                    line: span.start().line,
                    col: span.start().column,
                    message: format!("Import of weak cryptographic algorithm: {}.", reason),
                    snippet: ident.clone(),
                    fix: fix.into(),
                });
                break;
            }
        }
        syn::visit::visit_use_path(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = syn::parse_file(code).expect("failed to parse");
        let pass = WeakCrypto;
        pass.check_file(&file, Path::new("test.rs"))
    }

    #[test]
    fn detects_md5_use() {
        let findings = check("use md5::compute;");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.message.contains("MD5")));
    }

    #[test]
    fn detects_sha1_type() {
        let findings = check("fn hash(data: &[u8]) { let h = Sha1::new(); }");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.message.contains("SHA-1")));
    }

    #[test]
    fn detects_des() {
        let findings = check("use des::Des;");
        assert!(!findings.is_empty());
    }

    #[test]
    fn detects_ecb_mode() {
        let findings = check("type AesEcb = Ecb<Aes128, NoPadding>;");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.message.contains("ECB")));
    }

    #[test]
    fn allows_sha256() {
        let findings = check("use sha2::Sha256;");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_aes() {
        let findings = check("use aes::Aes256;");
        assert!(findings.is_empty());
    }
}
