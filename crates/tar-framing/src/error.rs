use std::io;

use crate::{ArchiveFormat, BLOCK_SIZE, GnuKind, MemberKind, stream::DataOwner};

/// An error encountered at an absolute position in a tar stream.
#[derive(Debug, thiserror::Error)]
#[error("at byte {position}: {inner}")]
pub struct FrameError {
    /// The absolute byte position associated with the failure.
    pub position: u64,
    /// The specific failure encountered at `position`.
    #[source]
    pub inner: FrameErrorInner,
}

impl FrameError {
    pub(crate) fn at(position: u64, inner: FrameErrorInner) -> Self {
        Self { position, inner }
    }

    pub(crate) fn arithmetic_overflow(position: u64, context: &'static str) -> Self {
        Self::at(position, FrameErrorInner::ArithmeticOverflow { context })
    }

    pub(crate) fn deleted_pax_metadata(position: u64, keyword: &'static str) -> Self {
        Self::at(position, FrameErrorInner::DeletedPaxMetadata { keyword })
    }

    pub(crate) fn dangling_global_pax(position: u64) -> Self {
        Self::at(position, FrameErrorInner::DanglingGlobalPax)
    }

    pub(crate) fn invalid_gnu_metadata(position: u64, kind: GnuKind, reason: &'static str) -> Self {
        Self::at(
            position,
            FrameErrorInner::InvalidGnuMetadata { kind, reason },
        )
    }

    pub(crate) fn invalid_member_size(position: u64, kind: MemberKind, size: u64) -> Self {
        Self::at(position, FrameErrorInner::InvalidMemberSize { kind, size })
    }

    pub(crate) fn invalid_pax_records(position: u64, reason: &'static str) -> Self {
        Self::at(position, FrameErrorInner::InvalidPaxRecords { reason })
    }

    pub(crate) fn truncated_payload(position: u64, owner: DataOwner, remaining: u64) -> Self {
        Self::at(
            position,
            FrameErrorInner::TruncatedPayload { owner, remaining },
        )
    }

    pub(crate) fn unexpected_eof(position: u64, expected: &'static str) -> Self {
        Self::at(position, FrameErrorInner::UnexpectedEof { expected })
    }

    pub(crate) fn unexpected_order(
        position: u64,
        expected: &'static str,
        found: &'static str,
    ) -> Self {
        Self::at(
            position,
            FrameErrorInner::UnexpectedOrder { expected, found },
        )
    }
}

/// Specific errors that can occur while processing tar frames.
#[derive(Debug, thiserror::Error)]
pub enum FrameErrorInner {
    /// The underlying reader failed.
    #[error("failed to read tar data")]
    Io {
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// The underlying stream ended in the middle of a logical block.
    #[error("incomplete tar block: read {read} of {BLOCK_SIZE} bytes")]
    IncompleteBlock {
        /// The number of bytes received for the incomplete block.
        read: usize,
    },
    /// A header did not identify either supported archive family.
    #[error("invalid tar identity: found {found:?}")]
    InvalidIdentity {
        /// The bytes found in the combined magic/version fields.
        found: [u8; 8],
    },
    /// A header checksum was malformed or did not match its contents.
    #[error("invalid tar checksum: stored {expected:?}, computed {actual}")]
    InvalidChecksum {
        /// The parsed stored checksum, or `None` if its field was malformed.
        expected: Option<u64>,
        /// The checksum computed from the header block.
        actual: u64,
    },
    /// A header's size field was not a strict number.
    /// The underlying format of the number might be octal or GNU-style base256.
    #[error("invalid tar size field: found {found:?}")]
    InvalidSize {
        /// The bytes found in the size field.
        found: [u8; 12],
    },
    /// An ordinary member header's mode field cannot be decoded.
    #[error("invalid tar mode field: found {found:?}")]
    InvalidMode {
        /// The bytes found in the mode field.
        found: [u8; 8],
    },
    /// A tar type is not supported within the selected archive family.
    #[error("unsupported tar typeflag {typeflag:?}")]
    UnsupportedTypeflag {
        /// The unsupported typeflag byte.
        typeflag: u8,
    },
    /// A header from another archive family appeared after family detection.
    #[error("archive format changed from {expected:?} to {found:?}")]
    FormatMismatch {
        /// The archive family selected by an earlier header.
        expected: ArchiveFormat,
        /// The archive family identified by this header.
        found: ArchiveFormat,
    },
    /// A valid block appeared in a position where another block type was required.
    #[error("unexpected tar block: expected {expected}, found {found}")]
    UnexpectedOrder {
        /// A description of the required block.
        expected: &'static str,
        /// A description of the block received.
        found: &'static str,
    },
    /// A pax payload did not consist of valid extended header records.
    #[error("invalid pax records: {reason}")]
    InvalidPaxRecords {
        /// A concise description of the grammar violation.
        reason: &'static str,
    },
    /// A pax text component that must be UTF-8 is not valid UTF-8.
    #[error("pax records contain invalid UTF-8 text")]
    InvalidPaxUtf8,
    /// A pax record keyword is neither standard nor an accepted namespaced extension.
    #[error("invalid or unknown pax keyword {keyword:?}")]
    InvalidPaxKeyword {
        /// The rejected keyword.
        keyword: String,
    },
    /// A pax decimal integer field is malformed or exceeds this API's integer range.
    #[error("invalid pax {keyword} value: {value:?}")]
    InvalidPaxInteger {
        /// The affected standard keyword.
        keyword: &'static str,
        /// The rejected textual value.
        value: String,
    },
    /// A pax file-time value is malformed or exceeds this API's integer range.
    #[error("invalid pax {keyword} time value: {value:?}")]
    InvalidPaxTime {
        /// The affected standard keyword.
        keyword: &'static str,
        /// The rejected textual value.
        value: String,
    },
    /// A pax `hdrcharset` record requests text encoding unsupported by this API.
    #[error("unsupported pax hdrcharset value {value:?}")]
    UnsupportedPaxCharset {
        /// The unsupported character-set identifier.
        value: String,
    },
    /// A GNU long-name or long-link metadata payload is not a valid value.
    #[error("malformed GNU {kind:?} metadata payload: {reason}")]
    InvalidGnuMetadata {
        /// The GNU metadata extension being decoded.
        kind: GnuKind,
        /// The reason the metadata value was rejected.
        reason: &'static str,
    },
    /// A pax record removed metadata required to interpret a member.
    #[error("pax metadata {keyword:?} deletes a required member field")]
    DeletedPaxMetadata {
        /// The standard pax keyword that deleted its header fallback.
        keyword: &'static str,
    },
    /// A global pax header was not followed by an ordinary member.
    #[error("global pax extended header is not followed by an ordinary member")]
    DanglingGlobalPax,
    /// A framing offset or record length overflowed.
    #[error("arithmetic overflow while computing {context}")]
    ArithmeticOverflow {
        /// The computation that overflowed.
        context: &'static str,
    },
    /// A member's effective size is invalid for its type.
    #[error("member type {kind:?} cannot carry payload size {size}")]
    InvalidMemberSize {
        /// The member type.
        kind: MemberKind,
        /// The effective payload size.
        size: u64,
    },
    /// The stream ended while a payload still required bytes.
    #[error("unexpected end of stream: {owner:?} payload needs {remaining} more bytes")]
    TruncatedPayload {
        /// The kind of payload being read.
        owner: DataOwner,
        /// The remaining unpadded payload length.
        remaining: u64,
    },
    /// The stream ended while a required member header was pending.
    #[error("unexpected end of stream: expected {expected}")]
    UnexpectedEof {
        /// A description of the required next input.
        expected: &'static str,
    },
    /// The two-block end marker was absent or incomplete.
    #[error("missing two-block end-of-archive marker")]
    MissingEndMarker,
    /// The first zero terminator block was not followed by a second zero block.
    #[error("invalid end-of-archive marker: expected a second zero block")]
    InvalidEndMarker,
}
