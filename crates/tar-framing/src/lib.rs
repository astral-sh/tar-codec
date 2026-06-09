//! Low level framing of tar streams.
//!
//! This crate provides two APIs:
//!
//! - [`stream`] is a low-level, lossless per-block framing API.
//! - [`logical`] is a medium-level, assembled member reader API.
//!
//! [`stream`] provides the basic static machine enforcement for a tar
//! stream, including ensuring that any given stream is either strictly
//! pax *or* GNU and not a mix of the two. [`logical`] is layered on top
//! of [`stream`] and provides APIs for accessing the "effective" metadata
//! for each assembled member.

mod error;
mod header;
pub mod logical;
mod pax;
pub mod stream;
#[cfg(test)]
mod test_support;
pub mod write;

pub use error::{FrameError, FrameErrorInner};
pub use pax::{HdrCharset, PaxExtension, PaxRecord, PaxState, PaxString, PaxValue};

/// The size of a logical tar record.
pub const BLOCK_SIZE: usize = 512;

/// A single tar block.
pub type Block = [u8; BLOCK_SIZE];

/// An automatically detected, mutually exclusive tar archive family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveFormat {
    /// pax ustar headers with optional pax extended headers.
    Pax,
    /// Old GNU tar headers with optional `L` and `K` extension entries.
    Gnu,
}

/// The scope of a pax extended header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaxKind {
    /// A typeflag `x` header applying to the next ordinary member.
    Local,
    /// A typeflag `g` header updating persistent global values.
    Global,
}

/// The supported GNU metadata extension kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GnuKind {
    /// A typeflag `L` extension giving a long name for the next member.
    LongName,
    /// A typeflag `K` extension giving a long link name for the next member.
    LongLink,
}

/// A supported ordinary ustar member type.
///
/// These are shared across both pax and GNU tar streams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberKind {
    /// A regular file (`'0'` or NUL).
    Regular,
    /// A hard link (`'1'`).
    HardLink,
    /// A symbolic link (`'2'`).
    SymbolicLink,
    /// A character device (`'3'`).
    CharacterDevice,
    /// A block device (`'4'`).
    BlockDevice,
    /// A directory (`'5'`).
    Directory,
    /// A FIFO (`'6'`).
    Fifo,
    /// A contiguous file (`'7'`).
    Contiguous,
}
