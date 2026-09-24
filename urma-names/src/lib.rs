#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
pub mod config;
pub mod engine;
pub mod error;
pub mod index;
pub mod name;
pub mod payload;
pub mod scan;
pub mod state;
