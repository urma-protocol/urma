//! Optional archive engine. Opening an archive performs no network operations.
//! Applications may use their existing sources without depending on this crate
//! or running the standalone service.

pub mod archive;
pub mod cache;
pub mod client;
pub mod engine;
mod engine_sync;
mod error;
pub mod model;
pub mod names;
pub mod peer;
pub mod peer_codec;
mod peer_limits;
mod peer_parent;
pub mod peer_protocol;
pub mod peerbook;
pub mod projection;
pub mod retrieval;
mod scan;
pub mod service;
pub mod source;

pub use error::Error;
