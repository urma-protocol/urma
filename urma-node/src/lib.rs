//! Optional archive engine. Opening an archive performs no network operations.
//! Applications may use their existing sources without depending on this crate
//! or running the standalone service.

pub mod archive;
pub mod engine;
mod error;
pub mod model;
pub mod retrieval;
mod scan;
pub mod service;
pub mod source;

pub use error::Error;
