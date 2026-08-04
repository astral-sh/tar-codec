//! Asynchronous gzip streams with independently readable DEFLATE chapters.
//!
//! This crate operates on arbitrary byte streams. Archive framing and other
//! application-level record boundaries remain the caller's responsibility.
//!
//! # Attribution
//!
//! The chapter format, marker codec, backward-linked index, and gzip boundary
//! handling are derived from [`chapter-tgz`] by David Tolnay, originally
//! distributed under either the MIT license or Apache License, Version 2.0.
//!
//! [`chapter-tgz`]: https://github.com/dtolnay/chapter-tgz

mod marker;
mod reader;
mod writer;

pub use flate2::Compression;
pub use reader::{ChapterIndex, ChapterReader, ChapteredGzipReader};
pub use writer::ChapteredGzipWriter;

const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
