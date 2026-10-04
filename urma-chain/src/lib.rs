#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
pub mod config;
pub mod decode;
pub mod observation;
pub mod pow;
pub mod transaction;
pub mod validation;
