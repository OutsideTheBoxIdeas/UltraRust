// Test fixture: contains all 10 security check violations

use std::process::Command;
use std::path::Path;

// C-7: hardcoded_secrets - AWS key
fn get_aws_key() -> &'static str {
    "AKIAIOSFODNN7EXAMPLE"
}

// C-7: hardcoded_secrets - GitHub token
fn get_github_token() -> &'static str {
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
}

// C-8: command_injection - user input in arg()
fn run_command(user_input: &str) {
    Command::new("sh").arg("-c").arg(user_input).spawn();
}

// C-9: path_traversal - user input in join()
fn read_user_file(user_path: &str) {
    let _full = Path::new("/data").join(user_path);
}

// C-10: weak_crypto - MD5 usage
fn hash_md5(data: &[u8]) {
    let _h = md5::compute(data);
}

// C-10: weak_crypto - SHA1 usage
fn hash_sha1(data: &[u8]) {
    let _h = Sha1::new();
}

// C-11: insecure_deser - unbounded deserialization
fn parse_json(data: &str) {
    let _val: serde_json::Value = serde_json::from_str(data).unwrap();
}

// C-12: sql_injection - format string in query
fn get_user(db: &Pool, name: &str) {
    db.query(&format!("SELECT * FROM users WHERE name = '{}'", name));
}

// C-13: unbounded_reads - read_to_string
fn load_file(path: &Path) {
    let _content = std::fs::read_to_string(path);
}

// C-14: insecure_tls - disabled cert validation
fn make_client() {
    let _client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build();
}

// C-15: insecure_random - thread_rng in token generation
fn generate_token() -> u64 {
    let mut rng = thread_rng();
    rng.gen()
}

// C-16: timing_attack - non-constant-time comparison
fn verify_token(provided_token: &str, stored_token: &str) -> bool {
    provided_token == stored_token
}
