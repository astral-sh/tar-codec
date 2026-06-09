//! High-level decoding and encoding for tar archives.
//!
//! See [`decode`] for decoding/extraction and [`encode`] for pax encoding.

mod blocking;
mod name;

pub mod decode;
pub mod encode;

pub use name::{NameValidator, default_name_validator};
