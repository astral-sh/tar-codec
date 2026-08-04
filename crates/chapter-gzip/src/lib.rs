//! Asynchronous gzip streams with independently readable DEFLATE chapters.
//!
//! This crate operates on arbitrary byte streams. Archive framing and other
//! application-level record boundaries remain the caller's responsibility.

mod marker;
mod reader;
mod writer;

pub use flate2::Compression;
pub use reader::{ChapterIndex, ChapterReader, ChapteredGzipReader};
pub use writer::ChapteredGzipWriter;

const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
