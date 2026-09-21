#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
pub mod capture;
pub mod catalog;
pub mod chain;
pub mod config;
pub mod ingest;
pub mod inventory;
pub mod recover;
pub mod safety;
