//! High-level decoding and encoding for tar archives.
//!
//! For low- and medium-level handling of tar streams, see [`tar_framing`].
//!
//! Decoding and secure extraction are currently available through [`decode`].
//! Deterministic pure-pax encoding is available through [`encode`].

mod blocking;
mod name;

pub mod decode;
pub mod encode;

pub use name::{NameValidator, default_name_validator};
