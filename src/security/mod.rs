// Security checks (10 pattern-based security analyzers)

pub mod command_injection;
pub mod hardcoded_secrets;
pub mod insecure_deser;
pub mod insecure_random;
pub mod insecure_tls;
pub mod path_traversal;
pub mod sql_injection;
pub mod timing_attack;
pub mod unbounded_reads;
pub mod weak_crypto;
