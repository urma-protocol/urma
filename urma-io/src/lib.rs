#![deny(unused_must_use)]
#![deny(for_loops_over_fallibles)]
#![deny(dead_code)]
#![deny(unused_variables)]
#![deny(unused_assignments)]

mod access;
mod config;
mod error;
mod files;
pub use access::Access;
pub use config::output_parent;
pub use error::Error;
#[cfg(not(windows))]
pub use files::sync_directory;
pub use files::{read_bounded, write_new, write_replace};
mod native;
pub use native::digest;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{create_file, create_private_directory, read_private, read_regular, read_shared};
#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::{create_file, create_private_directory, read_private, read_regular, read_shared};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    create_file, create_private_directory, read_private, read_regular, read_shared, sync_directory,
};
