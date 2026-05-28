//! Lossless, block-oriented tar framing.
//!
//! The physical API emits one frame for each accepted non-terminator physical
//! tar block and preserves each source block verbatim.

use crate::{ArchiveFormat, BLOCK_SIZE, GnuKind, MemberKind, PaxKind, PaxRecord, State};

/// Represents a single non-terminator physical block in a tar stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frame {
    /// A local or global pax extended header block.
    Pax(PaxFrame),
    /// A GNU long-name or long-link extension header block.
    Gnu(GnuFrame),
    /// An ordinary POSIX-ustar or GNU member header block.
    Header(HeaderFrame),
    /// A pax or member payload block.
    Data(DataFrame),
}

/// A pax extended header block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaxFrame {
    /// The absolute byte position of this block in the source stream.
    pub position: u64,
    /// The lossless header block bytes.
    pub block: [u8; BLOCK_SIZE],
    /// Whether this header is local or global.
    pub kind: PaxKind,
    /// The number of bytes occupied by the extended header records.
    pub payload_size: u64,
}

/// A GNU metadata extension header block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GnuFrame {
    /// The absolute byte position of this block in the source stream.
    pub position: u64,
    /// The lossless header block bytes.
    pub block: [u8; BLOCK_SIZE],
    /// The GNU extension kind.
    pub kind: GnuKind,
    /// The number of metadata payload bytes following the header.
    pub payload_size: u64,
}

/// An ordinary member header block in the selected archive family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderFrame {
    /// The absolute byte position of this block in the source stream.
    pub position: u64,
    /// The lossless header block bytes.
    pub block: [u8; BLOCK_SIZE],
    /// The member type identified by the header.
    pub kind: MemberKind,
    /// The size encoded directly in the member header field.
    pub declared_size: u64,
    /// The size after applying applicable pax `size` records, or `None` if deleted.
    pub effective_size: Option<u64>,
    /// The number of payload bytes for which data frames will be emitted.
    pub payload_size: u64,
    /// Effective global pax records active for this member, including deletions.
    pub global_pax_records: Vec<PaxRecord>,
    /// Parsed local pax records that apply to this member, in input order.
    pub local_pax_records: Vec<PaxRecord>,
}

/// The payload entry to which a data block belongs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataOwner {
    /// Payload bytes belonging to a pax extended header.
    Pax(PaxKind),
    /// Payload bytes belonging to a GNU metadata extension.
    Gnu(GnuKind),
    /// Payload bytes belonging to an ordinary archive member.
    Member,
}

/// A payload physical block.
///
/// This can be "real" data for e.g. a file member, or it can be the payload of a pax
/// or GNU header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataFrame {
    /// The absolute byte position of this block in the source stream.
    pub position: u64,
    /// The lossless payload block bytes, including any final padding.
    pub block: [u8; BLOCK_SIZE],
    /// The number of meaningful payload bytes in this block.
    pub len: usize,
    /// Whether this block carries metadata-extension or member data.
    pub owner: DataOwner,
    /// Parsed records completed by this final pax payload block.
    ///
    /// This is `Some` only for the last data block belonging to a local or
    /// global pax header; other payload data carries `None`.
    pub completed_pax_records: Option<Vec<PaxRecord>>,
}

/// A strict stream of POSIX-pax or GNU frames sourced from an underlying reader.
pub struct TarStream<R> {
    pub(super) position: u64,
    pub(super) inner: R,
    pub(super) block: [u8; BLOCK_SIZE],
    pub(super) block_len: usize,
    pub(super) format: Option<ArchiveFormat>,
    pub(super) global_pax_records: Vec<PaxRecord>,
    pub(super) state: State,
}
