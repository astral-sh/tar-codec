//! Low level framing of tar streams.
//!
//! This crate provides the lossless block-level [`stream`] framing API and
//! the assembled member-level [`logical`] reader API.
//!
//! The stream is strict in the sense that it defines a state machine
//! that enforces the pax (ustar superset) or GNU format rules
//! and rejects streams that attempt to combine the two formats or that
//! are otherwise ambiguous.

mod error;
pub mod logical;
mod pax;
pub mod stream;
#[cfg(test)]
mod test_support;

pub use error::{FrameError, FrameErrorInner};
pub use pax::{HdrCharset, PaxRecord, PaxString, PaxValue};

/// The size of a logical tar record.
pub const BLOCK_SIZE: usize = 512;

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberKind {
    /// A regular file (`'0'` or NUL).
    Regular,
    /// A hard link (`'1'`), including pax `linkdata` payloads.
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
