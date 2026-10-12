//! Explicitly configured, optional loopback access to an URMA archive service.
//! This crate neither opens an archive nor starts a daemon or peer network.
//! Responses are supplied by the trusted local operator; typed decoding is not
//! independent cryptographic verification or evidence of chain completeness.
mod client;
mod error;
pub mod model;
pub mod names;
pub mod projection;

pub use client::Client;
pub use error::Error;
