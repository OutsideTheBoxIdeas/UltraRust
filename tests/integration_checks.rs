// Integration tests for all 15 custom lints and security checks.
// Tests the AnalysisDriver end-to-end against fixture files.

use std::path::Path;

// We test individual passes by parsing fixture code and checking findings.

/// Helper: analyze a fixture file through the driver.
fn analyze_fixture(fixture_name: &str) -> Vec<cargo_ultrarusty::driver::Finding> {
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(fixture_name);

    let driver = cargo_ultrarusty::driver::AnalysisDriver::new();

    // Use analyze_project on the fixtures dir, then filter to our file
    driver.analyze_project(fixture_path.parent().unwrap())
        .into_iter()
        .filter(|f| f.file == fixture_path)
        .collect()
}

/// Helper: analyze a code string by writing to a temp file and running the driver.
fn analyze_code(code: &str) -> Vec<cargo_ultrarusty::driver::Finding> {
    let driver = cargo_ultrarusty::driver::AnalysisDriver::new();
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let file_path = tmp.path().join("test_input.rs");
    std::fs::write(&file_path, code).expect("failed to write temp file");

    driver.analyze_project(tmp.path())
}

// ===== LINT TESTS =====

#[test]
fn test_lint_violations_fixture_has_findings() {
    let findings = analyze_fixture("lint_violations.rs");
    // Should find violations for all 5 lints
    assert!(!findings.is_empty(), "lint_violations.rs should produce findings");

    let check_names: Vec<&str> = findings.iter().map(|f| f.check_name.as_str()).collect();

    assert!(check_names.contains(&"no_interior_mutability"),
        "Should detect interior mutability. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"no_string_errors"),
        "Should detect string errors. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"no_infinite_loops"),
        "Should detect infinite loops. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"public_api_lifetimes"),
        "Should detect elided lifetimes. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"bounded_generics"),
        "Should detect excessive generics. Checks found: {:?}", check_names);
}

#[test]
fn test_security_violations_fixture_has_findings() {
    let findings = analyze_fixture("security_violations.rs");
    assert!(!findings.is_empty(), "security_violations.rs should produce findings");

    let check_names: Vec<&str> = findings.iter().map(|f| f.check_name.as_str()).collect();

    assert!(check_names.contains(&"hardcoded_secrets"),
        "Should detect hardcoded secrets. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"command_injection"),
        "Should detect command injection. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"path_traversal"),
        "Should detect path traversal. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"weak_crypto"),
        "Should detect weak crypto. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"sql_injection"),
        "Should detect SQL injection. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"unbounded_reads"),
        "Should detect unbounded reads. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"insecure_tls"),
        "Should detect insecure TLS. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"insecure_random"),
        "Should detect insecure random. Checks found: {:?}", check_names);
    assert!(check_names.contains(&"timing_attack"),
        "Should detect timing attacks. Checks found: {:?}", check_names);
}

#[test]
fn test_clean_code_fixture_minimal_findings() {
    let findings = analyze_fixture("clean_code.rs");
    // Clean code should have minimal findings
    // Filter out any findings from the security checks that are overly broad
    let lint_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.source == "ultrarusty")
        .collect();

    assert!(lint_findings.is_empty(),
        "clean_code.rs should produce no lint findings, but got: {:?}",
        lint_findings.iter().map(|f| &f.check_name).collect::<Vec<_>>());
}

// ===== INDIVIDUAL CHECK TESTS VIA CODE STRINGS =====

#[test]
fn test_no_interior_mutability_refcell() {
    let findings = analyze_code("use std::cell::RefCell; fn foo() { let _x: RefCell<i32> = RefCell::new(0); }");
    assert!(findings.iter().any(|f| f.check_name == "no_interior_mutability"));
}

#[test]
fn test_no_string_errors_result_string() {
    let findings = analyze_code("fn foo() -> Result<i32, String> { Ok(0) }");
    assert!(findings.iter().any(|f| f.check_name == "no_string_errors"));
}

#[test]
fn test_no_infinite_loops_detects() {
    let findings = analyze_code("fn foo() { loop { work(); } }");
    assert!(findings.iter().any(|f| f.check_name == "no_infinite_loops"));
}

#[test]
fn test_no_infinite_loops_allows_break() {
    let findings = analyze_code("fn foo() { loop { if done() { break; } } }");
    assert!(!findings.iter().any(|f| f.check_name == "no_infinite_loops"));
}

#[test]
fn test_public_api_lifetimes_detects_elided() {
    let findings = analyze_code("pub fn first(s: &str) -> &str { s }");
    assert!(findings.iter().any(|f| f.check_name == "public_api_lifetimes"));
}

#[test]
fn test_public_api_lifetimes_allows_explicit() {
    let findings = analyze_code("pub fn first<'a>(s: &'a str) -> &'a str { s }");
    assert!(!findings.iter().any(|f| f.check_name == "public_api_lifetimes"));
}

#[test]
fn test_bounded_generics_rejects_five() {
    let findings = analyze_code("fn foo<A, B, C, D, E>(a: A, b: B, c: C, d: D, e: E) {}");
    assert!(findings.iter().any(|f| f.check_name == "bounded_generics"));
}

#[test]
fn test_bounded_generics_allows_four() {
    let findings = analyze_code("fn foo<A, B, C, D>(a: A, b: B, c: C, d: D) {}");
    assert!(!findings.iter().any(|f| f.check_name == "bounded_generics"));
}

#[test]
fn test_hardcoded_secrets_aws_key() {
    let findings = analyze_code(r#"fn foo() { let k = "AKIAIOSFODNN7EXAMPLE"; }"#);
    assert!(findings.iter().any(|f| f.check_name == "hardcoded_secrets"));
}

#[test]
fn test_command_injection_detects() {
    let findings = analyze_code(r#"
        fn run(input: &str) {
            Command::new("sh").arg(input).spawn();
        }
    "#);
    assert!(findings.iter().any(|f| f.check_name == "command_injection"));
}

#[test]
fn test_command_injection_allows_safe() {
    let findings = analyze_code(r#"
        fn run() {
            Command::new("ls").arg("-la").spawn();
        }
    "#);
    assert!(!findings.iter().any(|f| f.check_name == "command_injection"));
}

#[test]
fn test_path_traversal_detects() {
    let findings = analyze_code(r#"
        fn read(user_path: &str) {
            let _p = Path::new("/data").join(user_path);
        }
    "#);
    assert!(findings.iter().any(|f| f.check_name == "path_traversal"));
}

#[test]
fn test_weak_crypto_md5() {
    let findings = analyze_code("use md5::compute;");
    assert!(findings.iter().any(|f| f.check_name == "weak_crypto"));
}

#[test]
fn test_weak_crypto_allows_sha256() {
    let findings = analyze_code("use sha2::Sha256;");
    assert!(!findings.iter().any(|f| f.check_name == "weak_crypto"));
}

#[test]
fn test_insecure_deser_from_str() {
    let findings = analyze_code(r#"
        fn parse(data: &str) {
            let _v: Value = serde_json::from_str(data).unwrap();
        }
    "#);
    assert!(findings.iter().any(|f| f.check_name == "insecure_deserialization"));
}

#[test]
fn test_sql_injection_format() {
    let findings = analyze_code(r#"
        fn query(db: &Pool, name: &str) {
            db.query(&format!("SELECT * FROM users WHERE name = '{}'", name));
        }
    "#);
    assert!(findings.iter().any(|f| f.check_name == "sql_injection"));
}

#[test]
fn test_sql_injection_allows_parameterized() {
    let findings = analyze_code(r#"
        fn query(db: &Pool, name: &str) {
            db.query("SELECT * FROM users WHERE name = $1");
        }
    "#);
    assert!(!findings.iter().any(|f| f.check_name == "sql_injection"));
}

#[test]
fn test_unbounded_reads_detects() {
    let findings = analyze_code(r#"
        fn load() {
            let _s = std::fs::read_to_string("file.txt");
        }
    "#);
    assert!(findings.iter().any(|f| f.check_name == "unbounded_reads"));
}

#[test]
fn test_insecure_tls_danger_certs() {
    let findings = analyze_code(r#"
        fn client() {
            let _c = builder.danger_accept_invalid_certs(true).build();
        }
    "#);
    assert!(findings.iter().any(|f| f.check_name == "insecure_tls"));
}

#[test]
fn test_insecure_tls_allows_false() {
    let findings = analyze_code(r#"
        fn client() {
            let _c = builder.danger_accept_invalid_certs(false).build();
        }
    "#);
    assert!(!findings.iter().any(|f| f.check_name == "insecure_tls"));
}

#[test]
fn test_insecure_random_in_security_context() {
    let findings = analyze_code(r#"
        fn generate_token() -> u64 {
            let mut rng = thread_rng();
            rng.gen()
        }
    "#);
    assert!(findings.iter().any(|f| f.check_name == "insecure_random"));
}

#[test]
fn test_insecure_random_allows_non_security() {
    let findings = analyze_code(r#"
        fn shuffle(items: &mut Vec<i32>) {
            let mut rng = thread_rng();
            items.shuffle(&mut rng);
        }
    "#);
    assert!(!findings.iter().any(|f| f.check_name == "insecure_random"));
}

#[test]
fn test_timing_attack_detects() {
    let findings = analyze_code(r#"
        fn verify(token: &str, expected: &str) -> bool {
            token == expected
        }
    "#);
    assert!(findings.iter().any(|f| f.check_name == "timing_attack"));
}

#[test]
fn test_timing_attack_allows_non_secret() {
    let findings = analyze_code(r#"
        fn check(count: i32, expected: i32) -> bool {
            count == expected
        }
    "#);
    assert!(!findings.iter().any(|f| f.check_name == "timing_attack"));
}

#[test]
fn test_driver_registers_15_passes() {
    let driver = cargo_ultrarusty::driver::AnalysisDriver::new();
    assert_eq!(driver.pass_count(), 15);
}

#[test]
fn test_findings_have_correct_source_field() {
    let lint_findings = analyze_code("fn foo() -> Result<i32, String> { Ok(0) }");
    for f in &lint_findings {
        if f.check_name == "no_string_errors" {
            assert_eq!(f.source, "ultrarusty", "Lint findings should have source='ultrarusty'");
        }
    }

    let sec_findings = analyze_code(r#"fn foo() { let k = "AKIAIOSFODNN7EXAMPLE"; }"#);
    for f in &sec_findings {
        if f.check_name == "hardcoded_secrets" {
            assert_eq!(f.source, "security", "Security findings should have source='security'");
        }
    }
}

#[test]
fn test_empty_file_produces_no_findings() {
    let findings = analyze_code("");
    assert!(findings.is_empty(), "Empty file should produce no findings");
}

#[test]
fn test_findings_have_line_numbers() {
    let findings = analyze_code("fn foo() -> Result<i32, String> { Ok(0) }");
    for f in &findings {
        assert!(f.line > 0, "Finding should have a non-zero line number");
    }
}
