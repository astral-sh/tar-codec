//! High-level decoding and encoding for tar archives.
//!
//! See [`decode`] for decoding/extraction and [`encode`] for pax encoding.
//!
//! ## Security
//!
//! Like other tar parsers, tar-codec assumes that it has unique access
//! to the target directory (the "extraction root") when extracting.
//! Concurrent mutation of the target directory is outside of the threat
//! model.
//! See the [repository's SECURITY.md](https://github.com/astral-sh/tar-codec/blob/main/SECURITY.md)
//! for more information.

mod blocking;
mod name;

pub mod decode;
pub mod encode;

pub use name::{NameValidator, default_name_validator};
