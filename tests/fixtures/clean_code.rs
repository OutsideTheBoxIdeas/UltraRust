// Test fixture: clean code that should produce NO findings

use std::collections::BTreeMap;

// Proper error type
#[derive(Debug)]
enum AppError {
    NotFound,
    InvalidInput(String),
}

// Result with proper error type
fn parse_input(s: &str) -> Result<i32, AppError> {
    s.parse::<i32>().map_err(|_| AppError::InvalidInput(s.to_string()))
}

// Explicit lifetimes on pub fn
pub fn first_word<'a>(s: &'a str) -> &'a str {
    s.split_whitespace().next().unwrap_or("")
}

// 4 type params (at the limit, not over)
fn transform<A, B, C, D>(a: A, b: B, c: C, d: D) {}

// No interior mutability
struct Config {
    name: String,
    value: i32,
}

// Loop with break
fn process_items(items: &[i32]) {
    loop {
        if items.is_empty() {
            break;
        }
        return;
    }
}

// Private function - lifetimes are fine to elide
fn helper(s: &str) -> &str {
    s
}

// No reference in return type - fine
pub fn compute(x: &i32) -> i32 {
    *x * 2
}
