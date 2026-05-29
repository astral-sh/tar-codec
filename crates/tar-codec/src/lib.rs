//! High-level decoding and encoding for tar archives.
//!
//! Decoding and secure extraction are currently available through [`decode`].
//! Deterministic pure-pax encoding is available through [`encode`].

pub mod decode;
pub mod encode;
