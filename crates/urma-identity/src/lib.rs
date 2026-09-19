#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
pub mod error;
pub mod identity;
pub mod keyring;
pub mod keys;
pub mod phrase;
pub mod vault;
