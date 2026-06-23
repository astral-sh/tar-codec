use std::io;

use crate::{ArchiveFormat, BLOCK_SIZE, GnuKind, UstarKind, pax::PaxError, stream::DataOwner};

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

    pub(crate) fn invalid_gnu_metadata(position: u64, kind: GnuKind, reason: &'static str) -> Self {
        Self::at(
            position,
            FrameErrorInner::InvalidGnuMetadata { kind, reason },
        )
    }

    pub(crate) fn invalid_pax_record(position: u64, source: PaxError) -> Self {
        Self::at(position, FrameErrorInner::InvalidPaxRecord { source })
    }

    pub(crate) fn truncated_payload(position: u64, owner: DataOwner, remaining: u64) -> Self {
        Self::at(
            position,
            FrameErrorInner::TruncatedPayload { owner, remaining },
        )
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
    /// An ordinary ustar member header's numeric field was not strict octal.
    #[error("invalid ustar {field} field: expected strict octal, found {found:?}")]
    InvalidUstarNumericField {
        /// The name of the malformed header field.
        field: &'static str,
        /// The bytes found in the malformed header field.
        found: Vec<u8>,
    },
    /// An ordinary ustar member header's string field had no NUL terminator.
    #[error("invalid ustar {field} field: missing NUL terminator")]
    UnterminatedUstarStringField {
        /// The name of the unterminated header field.
        field: &'static str,
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
    /// A pax extended-header record could not be parsed.
    #[error("{source}")]
    InvalidPaxRecord {
        /// The pax parsing failure.
        #[source]
        source: PaxError,
    },
    /// A metadata extension declares more data than the configured format limit.
    #[error("{format} extension payload size {size} exceeds configured limit {limit}")]
    ExtensionTooLarge {
        /// The archive family containing the extension.
        format: ArchiveFormat,
        /// The extension payload size declared in its header.
        size: u64,
        /// The configured maximum extension payload size.
        limit: u64,
    },
    /// Consecutive global pax extensions contain more metadata than the configured limit.
    #[error("global pax extension payload total {size} exceeds configured limit {limit}")]
    GlobalPaxExtensionsTooLarge {
        /// The cumulative declared size including the rejected extension.
        size: u64,
        /// The configured maximum cumulative payload size.
        limit: u64,
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
    /// An ordinary member has no effective pathname after applying extensions.
    #[error("ordinary member has an empty effective path")]
    EmptyMemberPath,
    /// An effective member path or link target contains an embedded NUL byte.
    #[error("effective member {field} contains a NUL byte")]
    NulInMemberName {
        /// The effective metadata field containing the NUL byte.
        field: &'static str,
    },
    /// A framing offset or record length overflowed.
    #[error("arithmetic overflow while computing {context}")]
    ArithmeticOverflow {
        /// The computation that overflowed.
        context: &'static str,
    },
    /// A member's declared or effective size is invalid for its type.
    #[error("member type {kind:?} cannot carry payload size {size}")]
    InvalidMemberSize {
        /// The member type.
        kind: UstarKind,
        /// The rejected declared or effective payload size.
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
