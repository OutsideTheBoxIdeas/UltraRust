// Test fixture: contains all 5 custom lint violations

use std::cell::RefCell;
use std::cell::Cell;
use std::cell::UnsafeCell;

// C-2: no_interior_mutability - RefCell usage
fn uses_refcell() {
    let _cache: RefCell<Vec<i32>> = RefCell::new(Vec::new());
}

// C-2: no_interior_mutability - Cell usage
struct CellHolder {
    value: Cell<bool>,
}

// C-2: no_interior_mutability - UnsafeCell usage
struct RawHolder {
    inner: UnsafeCell<u8>,
}

// C-3: no_string_errors - Result<T, String>
fn parse_data(s: &str) -> Result<i32, String> {
    s.parse::<i32>().map_err(|e| e.to_string())
}

// C-3: no_string_errors - Result<T, &str>
fn validate(input: &str) -> Result<(), &str> {
    if input.is_empty() {
        Err("empty input")
    } else {
        Ok(())
    }
}

// C-4: no_infinite_loops - loop without break
fn infinite_worker() {
    loop {
        do_work();
    }
}

// C-5: public_api_lifetimes - elided lifetimes on pub fn
pub fn first_word(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or("")
}

// C-5: public_api_lifetimes - another elided lifetime
pub fn get_ref(items: &[i32]) -> &i32 {
    &items[0]
}

// C-6: bounded_generics - too many type params (5 > 4)
fn over_generic<A, B, C, D, E>(a: A, b: B, c: C, d: D, e: E) {}

// C-6: bounded_generics - too many on struct (6 > 4)
struct TooGeneric<A, B, C, D, E, F> {
    a: A, b: B, c: C, d: D, e: E, f: F,
}

fn do_work() {}
