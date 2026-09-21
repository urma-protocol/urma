#![deny(unused_must_use)]
#![deny(for_loops_over_fallibles)]
#![deny(dead_code)]
#![deny(unused_variables)]
#![deny(unused_assignments)]

mod config;
mod error;
mod files;
pub use config::output_parent;
pub use error::Error;
pub use files::{read_bounded, write_new, write_replace};
mod native;
pub use native::{create_private_directory, digest, read_private, read_regular};
