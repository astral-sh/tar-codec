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
//!
//! This crate tries to faithfully extract pax or GNU entries without mixing the
//! two. See the sections below for compatibility notes.
//!
//! ## pax compatibility
//!
//! When decoding pax-formatted tar streams, tar-framing attempts to conform to
//! pax as specified in [POSIX.1-2024], i.e. "issue 8" of the POSIX specification.
//! See the [pax specification] for full details.
//!
//! However, there are a few small deviations from a pedantic reading of [POSIX.1-2024]
//! that are worth noting:
//!
//! - tar-framing permits a `ctime` pax record, despite not being specified in [POSIX.1-2024].
//!   The ctime record was removed from pax in [POSIX.1-2004] (which is itself a minor edit
//!   of POSIX.1-2001). However, many real-world pax archives still contain it, and its
//!   presence does not compromise or introduce ambiguity during framing.
//!
//! - tar-framing rejects directory entries (typeflag `'5'`) that present a nonzero size
//!   in their ustar header or pax `size` record. pax says that this size should be treated
//!   as a filesystem allocation hint rather than a physical size, but real-world parsers vary
//!   widely in how they handle it (some ignore it, others skip over that number of bytes, etc.).
//!
//! - tar-framing rejects regular file entries (typeflag `'0'` or `'\0'`) that include a trailing
//!   slash (e.g. `foo.txt/`). pax is ambiguous about to handle these cases: it notes that
//!   pre-ustar tar had no directory entry typeflag and thus a trailing slash was used
//!   to indicate a directory by convention, but does not prescribe that pax implementors
//!   honor this legacy behavior. We choose to reject it since it presents the same directory
//!   size problem mentioned above.
//!
//! - tar-framing rejects negative timestamps as well as timestamps that would exceed the
//!   precision of a `u64`. pax allows both of these, although it notes that portable timestamps
//!   cannot be negative and that tools may reject such timestamps.
//!
//! - tar-framing silently removes fractional components from parsed timestamps. Timestamps
//!   are truncated to second precision.
//!
//! - tar-framing accepts wholly NUL `mode`, `uid`, `gid`, and `mtime` fields by default for
//!   compatibility with real-world pax writers. The missing mode is interpreted as zero and
//!   the other fields remain absent. This can be disabled with
//!   [`stream::TarStream::set_allow_all_nul_ustar_numeric_fields`].
//!
//! - tar-framing rejects typeflags that are not explicitly defined in pax. pax says to handle
//!   these as regular files (i.e. assuming their size is a physical size), but this has marginal
//!   benefit in practice.
//!
//! - tar-framing rejects `hdrcharset` pax records that aren't UTF-8 or `BINARY`. pax says
//!   that "additional names may be agreed between the originator and the recipient," but
//!   we are the recipient and we don't accept any other `hdrcharset` names.
//!
//! ## GNU compatibility
//!
//! When decoding GNU-formatted tar streams, tar-framing attempts to follow the
//! ["Basic Tar Format"] in the GNU docs. Specifically, tar-framing attempts
//! to follow the rules for the "old GNU" format, i.e. GNU tar's non-pax format.
//!
//! tar-framing intentionally only supports a subset of the GNU tar format:
//!
//! - The GNU "longname" and "longlink" (`'L'` and `'K'`) typeflags are supported,
//!   with similar path-precedence semantics as their pax record equivalents.
//!
//! - Other GNU-specific typeflags are **not** supported whatsoever, and produce
//!   a framing error. This includes sparse files (`'S'`) and multivolume headers
//!   (`'M'`).
//!
//! - tar-framing accepts the GNU-specific "base-256" encoding for numbers, but rejects
//!   negative encodings as well as any value that would exceed the precision of a `u64`.
//!   tar-framing also allows "base-256" encodings where the numeric value _would_ fit
//!   into an octal encoding in the alloted buffer/byte span; GNU technically says that
//!   this is reserved for future use.
//!
//! ## General compatibility
//!
//! Because pax and GNU both use ustar as their baseline, any compatibility aspect of pax
//! that is derived from ustar also applies during GNU tar decoding.
//!
//! Separately, higher-level crates (like tar-codec) may choose to apply additional
//! restrictions when processing logical archive members. For example, a consumer
//! of tar-framing may choose to reject vendor-specific pax records, or member names
//! that contain forbidden characters, or any other additional restriction.
//!
//! [POSIX.1-2024]: https://pubs.opengroup.org/onlinepubs/9799919799/
//! [pax specification]: https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html
//! [POSIX.1-2004]: https://pubs.opengroup.org/onlinepubs/009695399/toc.htm
//! ["Basic Tar Format"]: https://www.gnu.org/software/tar/manual/html_node/Standard.html

use std::fmt;

mod error;
pub mod header;
pub mod logical;
mod pax;
pub mod stream;
#[cfg(test)]
mod test_support;
pub mod write;

pub use error::{FrameError, FrameErrorInner};
pub use pax::{
    HdrCharset, PaxError, PaxExtension, PaxKeyword, PaxRecord, PaxState, PaxString, PaxValue,
};

/// The size of a logical tar record.
pub const BLOCK_SIZE: usize = 512;

/// The default maximum size in bytes of one local or global pax extension.
///
/// This is 256 KiB.
pub const DEFAULT_MAX_PAX_EXTENSION_SIZE: u64 = 256 * 1024;

/// The default maximum cumulative size of global pax extensions before one member.
///
/// This is 1 MiB.
pub const DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE: u64 = 4 * DEFAULT_MAX_PAX_EXTENSION_SIZE;

/// The default maximum size in bytes of one GNU metadata extension.
///
/// This is 128 KiB.
pub const DEFAULT_MAX_GNU_EXTENSION_SIZE: u64 = 128 * 1024;

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

impl fmt::Display for ArchiveFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pax => formatter.write_str("pax"),
            Self::Gnu => formatter.write_str("GNU"),
        }
    }
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
pub enum UstarKind {
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
