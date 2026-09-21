#![deny(
    unused_must_use,
    for_loops_over_fallibles,
    dead_code,
    unused_variables,
    unused_assignments
)]
mod error;
pub mod index;
pub mod reader;
pub mod view;

pub(crate) use error::ensure;
pub use error::{Error, SyncError};
