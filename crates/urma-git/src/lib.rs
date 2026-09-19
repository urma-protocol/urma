#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
pub mod checkout;
pub mod descriptor;
pub mod error;
pub mod git;
pub mod inventory;
pub mod review;
pub mod snapshot;
