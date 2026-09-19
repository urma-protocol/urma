#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
mod binding;
pub mod checkout;
pub mod config;
pub mod descriptor;
pub mod error;
pub mod git;
pub mod inventory;
pub mod plans;
pub mod proofs;
pub mod review;
pub mod snapshot;
pub mod workflows;
