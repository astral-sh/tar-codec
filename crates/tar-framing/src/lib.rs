//! Low level framing of tar streams.
//!
//! This crate provides a [`TarStream`] struct that turns an asynchronous
//! reader into a stream of physical [`Frame`]s, representing logical tar
//! blocks, and a [`TarReader`] that groups them into archive-level items.
//!
//! The stream is strict in the sense that it defines a state machine
//! that enforces the POSIX (meaning ustar and pax) or GNU format rules
//! and rejects streams that attempt to combine the two formats or that
//! are otherwise ambiguous.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

mod pax;

use pax::{
    PaxSize, apply_global as apply_global_pax_records, parse_records as parse_pax_records,
    size as pax_size,
};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_stream::{Stream, StreamExt};

pub use pax::{HdrCharset, PaxRecord, PaxValue};

/// The size of a logical tar record.
pub const BLOCK_SIZE: usize = 512;

const SIZE_RANGE: std::ops::Range<usize> = 124..136;
const CHECKSUM_RANGE: std::ops::Range<usize> = 148..156;
const TYPEFLAG_OFFSET: usize = 156;
const IDENTITY_RANGE: std::ops::Range<usize> = 257..265;
const POSIX_IDENTITY: &[u8; 8] = b"ustar\x0000";
const GNU_IDENTITY: &[u8; 8] = b"ustar  \0";

type PositionedBlock = (u64, [u8; BLOCK_SIZE]);

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
    fn at(position: u64, inner: FrameErrorInner) -> Self {
        Self { position, inner }
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
    /// A header's size field was not a strict POSIX octal value.
    #[error("invalid tar size field: found {found:?}")]
    InvalidSize {
        /// The bytes found in the size field.
        found: [u8; 12],
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
    /// A pax record could not be represented by this UTF-8-only API.
    #[error("pax records contain non-UTF-8 text")]
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
    /// A pax `hdrcharset` record requests text encoding unsupported by this UTF-8-only API.
    #[error("unsupported pax hdrcharset value {value:?}")]
    UnsupportedPaxCharset {
        /// The unsupported character-set identifier.
        value: String,
    },
    /// Pax records removed the size needed to frame a data-bearing member.
    #[error("member type {kind:?} has no effective size after applying pax records")]
    IndeterminateMemberSize {
        /// The member type whose payload length cannot be determined.
        kind: MemberKind,
    },
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
    /// The POSIX two-block end marker was absent or incomplete.
    #[error("missing two-block end-of-archive marker")]
    MissingEndMarker,
    /// The first zero terminator block was not followed by a second zero block.
    #[error("invalid end-of-archive marker: expected a second zero block")]
    InvalidEndMarker,
}

/// Represents a single non-terminator logical block in a tar stream.
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

/// An automatically detected, mutually exclusive tar archive family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveFormat {
    /// POSIX ustar headers with optional pax extended headers.
    PosixPax,
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

/// The supported GNU metadata extension kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GnuKind {
    /// A typeflag `L` extension giving a long name for the next member.
    LongName,
    /// A typeflag `K` extension giving a long link name for the next member.
    LongLink,
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

/// A payload logical block.
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

/// A fully parsed local or global pax extension header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaxHeader {
    /// The absolute byte position of the extension header block.
    pub position: u64,
    /// The lossless extension header block bytes.
    pub block: [u8; BLOCK_SIZE],
    /// Whether this extension is local or global.
    pub kind: PaxKind,
    /// The number of bytes occupied by the extended header records.
    pub payload_size: u64,
    /// Parsed pax records in archive order.
    pub records: Vec<PaxRecord>,
}

/// A GNU metadata extension header and its uninterpreted payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GnuHeader {
    /// The absolute byte position of the extension header block.
    pub position: u64,
    /// The lossless extension header block bytes.
    pub block: [u8; BLOCK_SIZE],
    /// The GNU extension kind.
    pub kind: GnuKind,
    /// The number of metadata payload bytes following the header.
    pub payload_size: u64,
    /// The meaningful metadata payload bytes, excluding tar padding.
    pub payload: Vec<u8>,
}

/// An ordinary member header in a logical archive item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberHeader {
    /// The absolute byte position of this header block in the source stream.
    pub position: u64,
    /// The lossless member header block bytes.
    pub block: [u8; BLOCK_SIZE],
    /// The member type identified by the header.
    pub kind: MemberKind,
    /// The size encoded directly in the member header field.
    pub declared_size: u64,
    /// The size after applying applicable pax `size` records, or `None` if deleted.
    pub effective_size: Option<u64>,
    /// The meaningful payload size belonging to this member.
    pub payload_size: u64,
}

/// Extension metadata attached to one ordinary archive member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberExtensions {
    /// POSIX-pax state applicable to an ordinary ustar member.
    PosixPax {
        /// Effective global records active for this member.
        global_records: Vec<PaxRecord>,
        /// A local extension header applying only to this member.
        local: Option<Box<PaxHeader>>,
    },
    /// GNU metadata headers applying to an ordinary GNU member.
    Gnu {
        /// Optional GNU long-name extension header.
        long_name: Option<Box<GnuHeader>>,
        /// Optional GNU long-link extension header.
        long_link: Option<Box<GnuHeader>>,
    },
}

/// One meaningful payload block belonging to an ordinary archive member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadBlock {
    /// The absolute byte position of this payload block.
    pub position: u64,
    /// The lossless payload block bytes, including any final padding.
    pub block: [u8; BLOCK_SIZE],
    /// The number of meaningful bytes in this block.
    pub len: usize,
}

/// A logical item produced by [`TarReader`].
pub enum LogicalFrame<'a, R> {
    /// A standalone global pax update.
    GlobalPax(Box<PaxHeader>),
    /// An ordinary archive member with attached local metadata and payload.
    Member(Box<MemberFrame<'a, R>>),
}

/// An ordinary archive member and its streaming payload cursor.
pub struct MemberFrame<'a, R> {
    /// The ordinary member header.
    pub header: MemberHeader,
    /// Extension metadata applying to this member.
    pub extensions: MemberExtensions,
    /// A cursor over the member payload bytes.
    pub payload: MemberPayload<'a, R>,
}

/// A streaming, typed cursor over one member's payload blocks.
pub struct MemberPayload<'a, R> {
    reader: &'a mut TarReader<R>,
}

/// The parser phase required before the next logical tar block can be emitted.
#[derive(Debug)]
enum State {
    /// No payload is pending; accept a header or the first zero end marker.
    AwaitingHeader,
    /// Consume the payload blocks declared by a local or global pax header.
    ReadingPax {
        kind: PaxKind,
        header_position: u64,
        remaining: u64,
        payload: Vec<u8>,
    },
    /// A local pax header has completed; require its ordinary ustar header.
    AwaitingUstarHeader {
        records: Vec<PaxRecord>,
        size: PaxSize,
    },
    /// Consume uninterpreted payload blocks for a GNU `L` or `K` extension.
    ReadingGnu {
        kind: GnuKind,
        remaining: u64,
        pending: PendingGnu,
    },
    /// GNU metadata is pending; accept another distinct extension or its member.
    AwaitingGnuMember { pending: PendingGnu },
    /// Consume the payload blocks declared for an ordinary member.
    ReadingMember { remaining: u64 },
    /// The first zero end marker was read; require the second zero block.
    AwaitingSecondZero,
    /// A valid two-block end marker was consumed; no further input is examined.
    Complete,
    /// An error has been emitted; subsequent polls return end-of-stream.
    Failed,
}

#[derive(Clone, Copy, Debug, Default)]
struct PendingGnu {
    long_name: bool,
    long_link: bool,
}

/// A strict stream of POSIX-pax or GNU frames sourced from an underlying reader.
pub struct TarStream<R> {
    position: u64,
    inner: R,
    block: [u8; BLOCK_SIZE],
    block_len: usize,
    format: Option<ArchiveFormat>,
    global_pax_records: Vec<PaxRecord>,
    state: State,
}

impl<R> TarStream<R> {
    /// Creates a new `TarStream` from the given reader.
    pub fn new(reader: R) -> Self {
        Self {
            position: 0,
            inner: reader,
            block: [0; BLOCK_SIZE],
            block_len: 0,
            format: None,
            global_pax_records: Vec::new(),
            state: State::AwaitingHeader,
        }
    }

    /// Returns the selected archive family after the first header is read.
    pub fn format(&self) -> Option<ArchiveFormat> {
        self.format
    }
}

impl<R: AsyncRead + Unpin> TarStream<R> {
    fn poll_read_block(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<PositionedBlock>, FrameError>> {
        while self.block_len < BLOCK_SIZE {
            let mut read_buf = ReadBuf::new(&mut self.block[self.block_len..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(source)) => {
                    return Poll::Ready(Err(FrameError::at(
                        self.position + self.block_len as u64,
                        FrameErrorInner::Io { source },
                    )));
                }
                Poll::Ready(Ok(())) => {
                    let read = read_buf.filled().len();
                    if read == 0 {
                        if self.block_len == 0 {
                            return Poll::Ready(Ok(None));
                        }
                        return Poll::Ready(Err(FrameError::at(
                            self.position,
                            FrameErrorInner::IncompleteBlock {
                                read: self.block_len,
                            },
                        )));
                    }
                    self.block_len += read;
                }
            }
        }

        let position = self.position;
        self.position = self
            .position
            .checked_add(BLOCK_SIZE as u64)
            .ok_or_else(|| {
                FrameError::at(
                    position,
                    FrameErrorInner::ArithmeticOverflow {
                        context: "stream position",
                    },
                )
            })?;
        self.block_len = 0;
        let block = std::mem::replace(&mut self.block, [0; BLOCK_SIZE]);
        Poll::Ready(Ok(Some((position, block))))
    }

    fn handle_eof(&mut self) -> FrameError {
        match &self.state {
            State::AwaitingHeader | State::AwaitingSecondZero => {
                FrameError::at(self.position, FrameErrorInner::MissingEndMarker)
            }
            State::ReadingPax {
                kind, remaining, ..
            } => FrameError::at(
                self.position,
                FrameErrorInner::TruncatedPayload {
                    owner: DataOwner::Pax(*kind),
                    remaining: *remaining,
                },
            ),
            State::AwaitingUstarHeader { .. } => FrameError::at(
                self.position,
                FrameErrorInner::UnexpectedEof {
                    expected: "ordinary ustar member header after a local pax header",
                },
            ),
            State::ReadingGnu {
                kind, remaining, ..
            } => FrameError::at(
                self.position,
                FrameErrorInner::TruncatedPayload {
                    owner: DataOwner::Gnu(*kind),
                    remaining: *remaining,
                },
            ),
            State::AwaitingGnuMember { .. } => FrameError::at(
                self.position,
                FrameErrorInner::UnexpectedEof {
                    expected: "ordinary GNU member header after a GNU metadata extension",
                },
            ),
            State::ReadingMember { remaining } => FrameError::at(
                self.position,
                FrameErrorInner::TruncatedPayload {
                    owner: DataOwner::Member,
                    remaining: *remaining,
                },
            ),
            State::Complete | State::Failed => FrameError::at(
                self.position,
                FrameErrorInner::UnexpectedEof {
                    expected: "no further input",
                },
            ),
        }
    }

    fn process_block(
        &mut self,
        position: u64,
        block: [u8; BLOCK_SIZE],
    ) -> Result<Option<Frame>, FrameError> {
        let state = std::mem::replace(&mut self.state, State::Failed);
        match state {
            State::AwaitingHeader => {
                if is_zero_block(&block) {
                    self.state = State::AwaitingSecondZero;
                    Ok(None)
                } else {
                    self.process_boundary_header(position, block).map(Some)
                }
            }
            State::ReadingPax {
                kind,
                header_position,
                mut remaining,
                mut payload,
            } => {
                let len = remaining.min(BLOCK_SIZE as u64) as usize;
                payload.extend_from_slice(&block[..len]);
                remaining -= len as u64;
                let completed_pax_records = if remaining == 0 {
                    let records = parse_pax_records(header_position, &payload)?;
                    match kind {
                        PaxKind::Local => {
                            let size = pax_size(&records);
                            self.state = State::AwaitingUstarHeader {
                                records: records.clone(),
                                size,
                            };
                        }
                        PaxKind::Global => {
                            apply_global_pax_records(&mut self.global_pax_records, records.clone());
                            self.state = State::AwaitingHeader;
                        }
                    }
                    Some(records)
                } else {
                    self.state = State::ReadingPax {
                        kind,
                        header_position,
                        remaining,
                        payload,
                    };
                    None
                };
                Ok(Some(Frame::Data(DataFrame {
                    position,
                    block,
                    len,
                    owner: DataOwner::Pax(kind),
                    completed_pax_records,
                })))
            }
            State::AwaitingUstarHeader { records, size } => {
                if is_zero_block(&block) {
                    return Err(FrameError::at(
                        position,
                        FrameErrorInner::UnexpectedOrder {
                            expected: "ordinary ustar member header after a local pax header",
                            found: "end-of-archive marker",
                        },
                    ));
                }
                let parsed = self.parse_format_checked_header(position, &block)?;
                if matches!(parsed.typeflag, b'x' | b'g') {
                    return Err(FrameError::at(
                        position,
                        FrameErrorInner::UnexpectedOrder {
                            expected: "ordinary ustar member header after a local pax header",
                            found: "another pax extended header",
                        },
                    ));
                }
                self.process_ustar_header(position, block, parsed, records, size)
                    .map(Some)
            }
            State::ReadingGnu {
                kind,
                mut remaining,
                pending,
            } => {
                let len = remaining.min(BLOCK_SIZE as u64) as usize;
                remaining -= len as u64;
                if remaining == 0 {
                    self.state = State::AwaitingGnuMember { pending };
                } else {
                    self.state = State::ReadingGnu {
                        kind,
                        remaining,
                        pending,
                    };
                }
                Ok(Some(Frame::Data(DataFrame {
                    position,
                    block,
                    len,
                    owner: DataOwner::Gnu(kind),
                    completed_pax_records: None,
                })))
            }
            State::AwaitingGnuMember { pending } => {
                if is_zero_block(&block) {
                    return Err(FrameError::at(
                        position,
                        FrameErrorInner::UnexpectedOrder {
                            expected: "ordinary GNU member header after a GNU metadata extension",
                            found: "end-of-archive marker",
                        },
                    ));
                }
                let parsed = self.parse_format_checked_header(position, &block)?;
                self.process_gnu_header(position, block, parsed, pending)
                    .map(Some)
            }
            State::ReadingMember { mut remaining } => {
                let len = remaining.min(BLOCK_SIZE as u64) as usize;
                remaining -= len as u64;
                if remaining == 0 {
                    self.state = State::AwaitingHeader;
                } else {
                    self.state = State::ReadingMember { remaining };
                }
                Ok(Some(Frame::Data(DataFrame {
                    position,
                    block,
                    len,
                    owner: DataOwner::Member,
                    completed_pax_records: None,
                })))
            }
            State::AwaitingSecondZero => {
                if !is_zero_block(&block) {
                    return Err(FrameError::at(position, FrameErrorInner::InvalidEndMarker));
                }
                self.state = State::Complete;
                Ok(None)
            }
            State::Complete => {
                self.state = State::Complete;
                Ok(None)
            }
            State::Failed => {
                self.state = State::Failed;
                Ok(None)
            }
        }
    }

    fn process_boundary_header(
        &mut self,
        position: u64,
        block: [u8; BLOCK_SIZE],
    ) -> Result<Frame, FrameError> {
        let parsed = self.parse_format_checked_header(position, &block)?;
        match self.format.expect("header selects an archive format") {
            ArchiveFormat::PosixPax => self.process_posix_boundary_header(position, block, parsed),
            ArchiveFormat::Gnu => {
                self.process_gnu_header(position, block, parsed, PendingGnu::default())
            }
        }
    }

    /// Parses a header and enforces the archive's single selected format.
    ///
    /// The first non-terminator header selects the format; later headers must
    /// match that selection before their family-specific fields are parsed.
    fn parse_format_checked_header(
        &mut self,
        position: u64,
        block: &[u8; BLOCK_SIZE],
    ) -> Result<ParsedHeader, FrameError> {
        let found = detect_format(position, block)?;
        if let Some(expected) = self.format
            && found != expected
        {
            return Err(FrameError::at(
                position,
                FrameErrorInner::FormatMismatch { expected, found },
            ));
        }
        let parsed = parse_header(position, block, found)?;
        self.format.get_or_insert(found);
        Ok(parsed)
    }

    /// Processes a POSIX header at an archive-member boundary, where a new
    /// pax extension or an ordinary ustar member may begin.
    ///
    /// Pax extension headers enter [`State::ReadingPax`]; ordinary ustar
    /// headers are delegated to [`Self::process_ustar_header`].
    fn process_posix_boundary_header(
        &mut self,
        position: u64,
        block: [u8; BLOCK_SIZE],
        parsed: ParsedHeader,
    ) -> Result<Frame, FrameError> {
        match parsed.typeflag {
            b'x' => self.process_pax_header(position, block, parsed.size, PaxKind::Local),
            b'g' => self.process_pax_header(position, block, parsed.size, PaxKind::Global),
            _ => {
                self.process_ustar_header(position, block, parsed, Vec::new(), PaxSize::Unspecified)
            }
        }
    }

    /// Emits a pax extension header and enters its payload-reading state.
    ///
    /// This is reached only from the POSIX boundary state, before any local
    /// pax records require an ordinary member header.
    fn process_pax_header(
        &mut self,
        position: u64,
        block: [u8; BLOCK_SIZE],
        payload_size: u64,
        kind: PaxKind,
    ) -> Result<Frame, FrameError> {
        if payload_size == 0 {
            return Err(FrameError::at(
                position,
                FrameErrorInner::InvalidPaxRecords {
                    reason: "extended header payload contains no records",
                },
            ));
        }
        self.state = State::ReadingPax {
            kind,
            header_position: position,
            remaining: payload_size,
            payload: Vec::new(),
        };
        Ok(Frame::Pax(PaxFrame {
            position,
            block,
            kind,
            payload_size,
        }))
    }

    /// Emits an ordinary ustar member header after applying pax size state.
    ///
    /// This handles both bare members and members required by
    /// [`State::AwaitingUstarHeader`], then enters member data reading when
    /// the effective member size requires payload blocks.
    fn process_ustar_header(
        &mut self,
        position: u64,
        block: [u8; BLOCK_SIZE],
        parsed: ParsedHeader,
        local_pax_records: Vec<PaxRecord>,
        local_size: PaxSize,
    ) -> Result<Frame, FrameError> {
        let kind = member_kind(position, parsed.typeflag)?;
        let effective_size = match local_size {
            PaxSize::Value(size) => Some(size),
            PaxSize::Deleted => None,
            PaxSize::Unspecified => match pax_size(&self.global_pax_records) {
                PaxSize::Value(size) => Some(size),
                PaxSize::Deleted => None,
                PaxSize::Unspecified => Some(parsed.size),
            },
        };
        let payload_size = posix_payload_size(position, kind, effective_size)?;
        self.state = if payload_size == 0 {
            State::AwaitingHeader
        } else {
            State::ReadingMember {
                remaining: payload_size,
            }
        };
        Ok(Frame::Header(HeaderFrame {
            position,
            block,
            kind,
            declared_size: parsed.size,
            effective_size,
            payload_size,
            global_pax_records: self.global_pax_records.clone(),
            local_pax_records,
        }))
    }

    fn process_gnu_header(
        &mut self,
        position: u64,
        block: [u8; BLOCK_SIZE],
        parsed: ParsedHeader,
        mut pending: PendingGnu,
    ) -> Result<Frame, FrameError> {
        let extension = match parsed.typeflag {
            b'L' => Some(GnuKind::LongName),
            b'K' => Some(GnuKind::LongLink),
            _ => None,
        };
        if let Some(kind) = extension {
            let already_seen = match kind {
                GnuKind::LongName => &mut pending.long_name,
                GnuKind::LongLink => &mut pending.long_link,
            };
            if *already_seen {
                return Err(FrameError::at(
                    position,
                    FrameErrorInner::UnexpectedOrder {
                        expected: "ordinary GNU member header or the other GNU metadata extension",
                        found: "duplicate GNU metadata extension",
                    },
                ));
            }
            *already_seen = true;
            self.state = if parsed.size == 0 {
                State::AwaitingGnuMember { pending }
            } else {
                State::ReadingGnu {
                    kind,
                    remaining: parsed.size,
                    pending,
                }
            };
            return Ok(Frame::Gnu(GnuFrame {
                position,
                block,
                kind,
                payload_size: parsed.size,
            }));
        }

        let kind = member_kind(position, parsed.typeflag)?;
        if pending.long_link && !matches!(kind, MemberKind::HardLink | MemberKind::SymbolicLink) {
            return Err(FrameError::at(
                position,
                FrameErrorInner::UnexpectedOrder {
                    expected: "hard-link or symbolic-link member after GNU long-link extension",
                    found: "non-link ordinary member",
                },
            ));
        }
        let payload_size = gnu_payload_size(position, kind, parsed.size)?;
        self.state = if payload_size == 0 {
            State::AwaitingHeader
        } else {
            State::ReadingMember {
                remaining: payload_size,
            }
        };
        Ok(Frame::Header(HeaderFrame {
            position,
            block,
            kind,
            declared_size: parsed.size,
            effective_size: Some(parsed.size),
            payload_size,
            global_pax_records: Vec::new(),
            local_pax_records: Vec::new(),
        }))
    }
}

impl<R: AsyncRead + Unpin> Stream for TarStream<R> {
    type Item = Result<Frame, FrameError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if matches!(this.state, State::Complete | State::Failed) {
                return Poll::Ready(None);
            }

            let (position, block) = match this.poll_read_block(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(Some(block))) => block,
                Poll::Ready(Ok(None)) => {
                    let error = this.handle_eof();
                    this.state = State::Failed;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Err(error)) => {
                    this.state = State::Failed;
                    return Poll::Ready(Some(Err(error)));
                }
            };

            match this.process_block(position, block) {
                Ok(Some(frame)) => return Poll::Ready(Some(Ok(frame))),
                Ok(None) => continue,
                Err(error) => {
                    this.state = State::Failed;
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }
    }
}

/// A logical reader that assembles physical frames into archive-level items.
///
/// Unlike [`TarStream`], this API attaches local pax or GNU extension
/// metadata to the ordinary member it describes. Global pax updates are
/// emitted independently because they remain active across member boundaries.
pub struct TarReader<R> {
    stream: TarStream<R>,
    payload_remaining: u64,
}

impl<R> TarReader<R> {
    /// Creates a new logical reader from an uncompressed tar reader.
    pub fn new(reader: R) -> Self {
        Self {
            stream: TarStream::new(reader),
            payload_remaining: 0,
        }
    }

    /// Returns the selected archive family after the first header is read.
    pub fn format(&self) -> Option<ArchiveFormat> {
        self.stream.format()
    }
}

impl<R: AsyncRead + Unpin> TarReader<R> {
    /// Returns the next global pax update or ordinary archive member.
    ///
    /// If the preceding member payload was not fully consumed, it is first
    /// drained and validated before the next logical item is returned.
    pub async fn next_frame(&mut self) -> Result<Option<LogicalFrame<'_, R>>, FrameError> {
        self.drain_payload().await?;

        let mut local_pax = None;
        let mut long_name = None;
        let mut long_link = None;
        loop {
            let Some(frame) = self.next_physical_frame().await? else {
                return Ok(None);
            };
            match frame {
                Frame::Pax(frame) => {
                    let header = self.read_pax_header(frame).await?;
                    match header.kind {
                        PaxKind::Global => {
                            return Ok(Some(LogicalFrame::GlobalPax(Box::new(header))));
                        }
                        PaxKind::Local => local_pax = Some(Box::new(header)),
                    }
                }
                Frame::Gnu(frame) => {
                    let header = self.read_gnu_header(frame).await?;
                    match header.kind {
                        GnuKind::LongName => long_name = Some(Box::new(header)),
                        GnuKind::LongLink => long_link = Some(Box::new(header)),
                    }
                }
                Frame::Header(header) => {
                    let format = self.stream.format().ok_or_else(|| {
                        self.unexpected_logical_frame(
                            header.position,
                            "selected archive format for an ordinary member header",
                            "ordinary member header without a format",
                        )
                    })?;
                    let extensions = match format {
                        ArchiveFormat::PosixPax => MemberExtensions::PosixPax {
                            global_records: header.global_pax_records.clone(),
                            local: local_pax,
                        },
                        ArchiveFormat::Gnu => MemberExtensions::Gnu {
                            long_name,
                            long_link,
                        },
                    };
                    let header = MemberHeader {
                        position: header.position,
                        block: header.block,
                        kind: header.kind,
                        declared_size: header.declared_size,
                        effective_size: header.effective_size,
                        payload_size: header.payload_size,
                    };
                    self.payload_remaining = header.payload_size;
                    return Ok(Some(LogicalFrame::Member(Box::new(MemberFrame {
                        header,
                        extensions,
                        payload: MemberPayload { reader: self },
                    }))));
                }
                Frame::Data(frame) => {
                    return Err(self.unexpected_logical_frame(
                        frame.position,
                        "extension header or ordinary member header",
                        "unattached payload data",
                    ));
                }
            }
        }
    }

    async fn next_physical_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        self.stream.next().await.transpose()
    }

    async fn read_pax_header(&mut self, frame: PaxFrame) -> Result<PaxHeader, FrameError> {
        loop {
            let Some(next) = self.next_physical_frame().await? else {
                return Err(self.unexpected_end("pax extension payload"));
            };
            match next {
                Frame::Data(data) if data.owner == DataOwner::Pax(frame.kind) => {
                    if let Some(records) = data.completed_pax_records {
                        return Ok(PaxHeader {
                            position: frame.position,
                            block: frame.block,
                            kind: frame.kind,
                            payload_size: frame.payload_size,
                            records,
                        });
                    }
                }
                other => {
                    return Err(self.unexpected_logical_frame(
                        frame_position(&other),
                        "pax extension payload",
                        frame_description(&other),
                    ));
                }
            }
        }
    }

    async fn read_gnu_header(&mut self, frame: GnuFrame) -> Result<GnuHeader, FrameError> {
        let mut remaining = frame.payload_size;
        let mut payload = Vec::new();
        while remaining != 0 {
            let Some(next) = self.next_physical_frame().await? else {
                return Err(self.unexpected_end("GNU metadata payload"));
            };
            match next {
                Frame::Data(data) if data.owner == DataOwner::Gnu(frame.kind) => {
                    let len = u64::try_from(data.len).map_err(|_| {
                        FrameError::at(
                            data.position,
                            FrameErrorInner::ArithmeticOverflow {
                                context: "GNU metadata payload length",
                            },
                        )
                    })?;
                    remaining = remaining.checked_sub(len).ok_or_else(|| {
                        FrameError::at(
                            data.position,
                            FrameErrorInner::UnexpectedOrder {
                                expected: "bounded GNU metadata payload",
                                found: "oversized GNU metadata payload",
                            },
                        )
                    })?;
                    payload.extend_from_slice(&data.block[..data.len]);
                }
                other => {
                    return Err(self.unexpected_logical_frame(
                        frame_position(&other),
                        "GNU metadata payload",
                        frame_description(&other),
                    ));
                }
            }
        }
        Ok(GnuHeader {
            position: frame.position,
            block: frame.block,
            kind: frame.kind,
            payload_size: frame.payload_size,
            payload,
        })
    }

    async fn next_payload_block(&mut self) -> Result<Option<PayloadBlock>, FrameError> {
        if self.payload_remaining == 0 {
            return Ok(None);
        }
        let Some(frame) = self.next_physical_frame().await? else {
            let remaining = std::mem::take(&mut self.payload_remaining);
            return Err(FrameError::at(
                self.stream.position,
                FrameErrorInner::TruncatedPayload {
                    owner: DataOwner::Member,
                    remaining,
                },
            ));
        };
        match frame {
            Frame::Data(data) if data.owner == DataOwner::Member => {
                let len = u64::try_from(data.len).map_err(|_| {
                    FrameError::at(
                        data.position,
                        FrameErrorInner::ArithmeticOverflow {
                            context: "member payload length",
                        },
                    )
                })?;
                self.payload_remaining =
                    self.payload_remaining.checked_sub(len).ok_or_else(|| {
                        FrameError::at(
                            data.position,
                            FrameErrorInner::UnexpectedOrder {
                                expected: "bounded member payload",
                                found: "oversized member payload",
                            },
                        )
                    })?;
                Ok(Some(PayloadBlock {
                    position: data.position,
                    block: data.block,
                    len: data.len,
                }))
            }
            other => {
                self.payload_remaining = 0;
                Err(self.unexpected_logical_frame(
                    frame_position(&other),
                    "ordinary member payload",
                    frame_description(&other),
                ))
            }
        }
    }

    async fn drain_payload(&mut self) -> Result<(), FrameError> {
        while self.next_payload_block().await?.is_some() {}
        Ok(())
    }

    fn unexpected_end(&self, expected: &'static str) -> FrameError {
        FrameError::at(
            self.stream.position,
            FrameErrorInner::UnexpectedEof { expected },
        )
    }

    fn unexpected_logical_frame(
        &self,
        position: u64,
        expected: &'static str,
        found: &'static str,
    ) -> FrameError {
        FrameError::at(
            position,
            FrameErrorInner::UnexpectedOrder { expected, found },
        )
    }
}

impl<R: AsyncRead + Unpin> MemberPayload<'_, R> {
    /// Returns the next meaningful payload block, excluding final padding in `len`.
    pub async fn next_block(&mut self) -> Result<Option<PayloadBlock>, FrameError> {
        self.reader.next_payload_block().await
    }

    /// Discards and validates all remaining payload blocks for this member.
    pub async fn skip(mut self) -> Result<(), FrameError> {
        while self.next_block().await?.is_some() {}
        Ok(())
    }
}

fn frame_position(frame: &Frame) -> u64 {
    match frame {
        Frame::Pax(frame) => frame.position,
        Frame::Gnu(frame) => frame.position,
        Frame::Header(frame) => frame.position,
        Frame::Data(frame) => frame.position,
    }
}

fn frame_description(frame: &Frame) -> &'static str {
    match frame {
        Frame::Pax(_) => "pax extension header",
        Frame::Gnu(_) => "GNU metadata header",
        Frame::Header(_) => "ordinary member header",
        Frame::Data(_) => "payload data",
    }
}

struct ParsedHeader {
    typeflag: u8,
    size: u64,
}

fn is_zero_block(block: &[u8; BLOCK_SIZE]) -> bool {
    block.iter().all(|byte| *byte == 0)
}

fn detect_format(position: u64, block: &[u8; BLOCK_SIZE]) -> Result<ArchiveFormat, FrameError> {
    match &block[IDENTITY_RANGE] {
        identity if identity == POSIX_IDENTITY => Ok(ArchiveFormat::PosixPax),
        identity if identity == GNU_IDENTITY => Ok(ArchiveFormat::Gnu),
        identity => Err(FrameError::at(
            position,
            FrameErrorInner::InvalidIdentity {
                found: identity.try_into().expect("fixed header range"),
            },
        )),
    }
}

fn parse_header(
    position: u64,
    block: &[u8; BLOCK_SIZE],
    format: ArchiveFormat,
) -> Result<ParsedHeader, FrameError> {
    let actual_checksum = block
        .iter()
        .enumerate()
        .map(|(offset, byte)| {
            if CHECKSUM_RANGE.contains(&offset) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    let expected_checksum = parse_octal(&block[CHECKSUM_RANGE]);
    if expected_checksum != Some(actual_checksum) {
        return Err(FrameError::at(
            position,
            FrameErrorInner::InvalidChecksum {
                expected: expected_checksum,
                actual: actual_checksum,
            },
        ));
    }

    let size_bytes: [u8; 12] = block[SIZE_RANGE].try_into().expect("fixed header range");
    let size = match format {
        ArchiveFormat::PosixPax => parse_octal(&size_bytes),
        ArchiveFormat::Gnu => parse_gnu_size(&size_bytes),
    }
    .ok_or_else(|| FrameError::at(position, FrameErrorInner::InvalidSize { found: size_bytes }))?;

    Ok(ParsedHeader {
        typeflag: block[TYPEFLAG_OFFSET],
        size,
    })
}

fn parse_octal(bytes: &[u8]) -> Option<u64> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return None;
    }
    let terminator = bytes.iter().position(|byte| matches!(byte, 0 | b' '))?;
    if terminator == 0
        || bytes[..terminator]
            .iter()
            .any(|byte| !matches!(byte, b'0'..=b'7'))
    {
        return None;
    }
    if bytes[terminator..]
        .iter()
        .any(|byte| !matches!(byte, 0 | b' '))
    {
        return None;
    }
    bytes[..terminator].iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(8)?.checked_add(u64::from(*byte - b'0'))
    })
}

fn parse_gnu_size(bytes: &[u8]) -> Option<u64> {
    if bytes.first() != Some(&0x80) {
        return parse_octal(bytes);
    }
    bytes[1..].iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(256)?.checked_add(u64::from(*byte))
    })
}

fn member_kind(position: u64, typeflag: u8) -> Result<MemberKind, FrameError> {
    match typeflag {
        0 | b'0' => Ok(MemberKind::Regular),
        b'1' => Ok(MemberKind::HardLink),
        b'2' => Ok(MemberKind::SymbolicLink),
        b'3' => Ok(MemberKind::CharacterDevice),
        b'4' => Ok(MemberKind::BlockDevice),
        b'5' => Ok(MemberKind::Directory),
        b'6' => Ok(MemberKind::Fifo),
        b'7' => Ok(MemberKind::Contiguous),
        _ => Err(FrameError::at(
            position,
            FrameErrorInner::UnsupportedTypeflag { typeflag },
        )),
    }
}

fn posix_payload_size(
    position: u64,
    kind: MemberKind,
    size: Option<u64>,
) -> Result<u64, FrameError> {
    match kind {
        MemberKind::Regular | MemberKind::HardLink | MemberKind::Contiguous => {
            size.ok_or_else(|| {
                FrameError::at(position, FrameErrorInner::IndeterminateMemberSize { kind })
            })
        }
        MemberKind::SymbolicLink => match size {
            Some(size) if size != 0 => Err(FrameError::at(
                position,
                FrameErrorInner::InvalidMemberSize { kind, size },
            )),
            _ => Ok(0),
        },
        MemberKind::CharacterDevice
        | MemberKind::BlockDevice
        | MemberKind::Directory
        | MemberKind::Fifo => Ok(0),
    }
}

fn gnu_payload_size(position: u64, kind: MemberKind, size: u64) -> Result<u64, FrameError> {
    match kind {
        MemberKind::Regular | MemberKind::Contiguous => Ok(size),
        MemberKind::HardLink | MemberKind::SymbolicLink if size != 0 => Err(FrameError::at(
            position,
            FrameErrorInner::InvalidMemberSize { kind, size },
        )),
        MemberKind::HardLink
        | MemberKind::SymbolicLink
        | MemberKind::CharacterDevice
        | MemberKind::BlockDevice
        | MemberKind::Directory
        | MemberKind::Fifo => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use super::*;

    struct ChunkedReader {
        bytes: Vec<u8>,
        position: usize,
        max_chunk: usize,
    }

    impl ChunkedReader {
        fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
            Self {
                bytes,
                position: 0,
                max_chunk,
            }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.position == self.bytes.len() {
                return Poll::Ready(Ok(()));
            }
            let len = self
                .max_chunk
                .min(buf.remaining())
                .min(self.bytes.len() - self.position);
            let start = self.position;
            let end = start + len;
            buf.put_slice(&self.bytes[start..end]);
            self.position = end;
            Poll::Ready(Ok(()))
        }
    }

    fn set_checksum(block: &mut [u8; BLOCK_SIZE]) {
        block[CHECKSUM_RANGE].fill(b' ');
        let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
        let encoded = format!("{checksum:06o}\0 ");
        block[CHECKSUM_RANGE].copy_from_slice(encoded.as_bytes());
    }

    fn header(typeflag: u8, size: u64) -> [u8; BLOCK_SIZE] {
        let mut block = [0; BLOCK_SIZE];
        block[..4].copy_from_slice(b"file");
        let encoded_size = format!("{size:011o}\0");
        block[SIZE_RANGE].copy_from_slice(encoded_size.as_bytes());
        block[TYPEFLAG_OFFSET] = typeflag;
        block[IDENTITY_RANGE].copy_from_slice(POSIX_IDENTITY);
        set_checksum(&mut block);
        block
    }

    fn gnu_header(typeflag: u8, size: u64) -> [u8; BLOCK_SIZE] {
        let mut block = header(typeflag, size);
        block[IDENTITY_RANGE].copy_from_slice(GNU_IDENTITY);
        set_checksum(&mut block);
        block
    }

    fn gnu_base256_header(typeflag: u8, size: u64) -> [u8; BLOCK_SIZE] {
        let mut block = gnu_header(typeflag, 0);
        block[SIZE_RANGE].fill(0);
        block[SIZE_RANGE.start] = 0x80;
        block[SIZE_RANGE.end - size.to_be_bytes().len()..SIZE_RANGE.end]
            .copy_from_slice(&size.to_be_bytes());
        set_checksum(&mut block);
        block
    }

    fn data(value: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut block = [0; BLOCK_SIZE];
        block[..value.len()].copy_from_slice(value);
        block
    }

    fn record(keyword: &str, value: &str) -> Vec<u8> {
        let suffix = format!(" {keyword}={value}\n");
        let mut len = suffix.len() + 1;
        loop {
            let encoded = format!("{len}{suffix}");
            if encoded.len() == len {
                return encoded.into_bytes();
            }
            len = encoded.len();
        }
    }

    fn append_block(bytes: &mut Vec<u8>, block: &[u8; BLOCK_SIZE]) {
        bytes.extend_from_slice(block);
    }

    fn append_payload(bytes: &mut Vec<u8>, payload: &[u8]) {
        for chunk in payload.chunks(BLOCK_SIZE) {
            append_block(bytes, &data(chunk));
        }
    }

    fn append_terminator(bytes: &mut Vec<u8>) {
        append_block(bytes, &[0; BLOCK_SIZE]);
        append_block(bytes, &[0; BLOCK_SIZE]);
    }

    fn collect(bytes: Vec<u8>, max_chunk: usize) -> Vec<Result<Frame, FrameError>> {
        let mut stream = TarStream::new(ChunkedReader::new(bytes, max_chunk));
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut frames = Vec::new();
        loop {
            match Pin::new(&mut stream).poll_next(&mut cx) {
                Poll::Ready(Some(frame)) => frames.push(frame),
                Poll::Ready(None) => return frames,
                Poll::Pending => panic!("test reader is never pending"),
            }
        }
    }

    fn last_error(frames: &[Result<Frame, FrameError>]) -> &FrameError {
        frames
            .last()
            .expect("stream should emit an item")
            .as_ref()
            .expect_err("last item should be an error")
    }

    fn last_error_inner(frames: &[Result<Frame, FrameError>]) -> &FrameErrorInner {
        &last_error(frames).inner
    }

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test reader is never pending"),
        }
    }

    #[test]
    fn frames_bare_member_across_fragmented_reads() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'0', 513));
        append_block(&mut bytes, &data(&[b'a'; BLOCK_SIZE]));
        append_block(&mut bytes, &data(b"b"));
        append_terminator(&mut bytes);

        let frames = collect(bytes, 7);
        assert_eq!(frames.len(), 3);
        let Frame::Header(header) = frames[0].as_ref().unwrap() else {
            panic!("expected member header");
        };
        assert_eq!(header.kind, MemberKind::Regular);
        assert_eq!(header.declared_size, 513);
        assert_eq!(header.effective_size, Some(513));
        assert_eq!(header.payload_size, 513);
        assert!(header.global_pax_records.is_empty());
        assert!(header.local_pax_records.is_empty());
        let Frame::Data(first) = frames[1].as_ref().unwrap() else {
            panic!("expected first data frame");
        };
        let Frame::Data(last) = frames[2].as_ref().unwrap() else {
            panic!("expected second data frame");
        };
        assert_eq!(first.len, BLOCK_SIZE);
        assert_eq!(last.len, 1);
        assert_eq!(last.owner, DataOwner::Member);
        assert!(first.completed_pax_records.is_none());
        assert!(last.completed_pax_records.is_none());
    }

    #[test]
    fn frames_multiblock_pax_records_and_applies_size_override() {
        let mut payload = record("comment", &"x".repeat(BLOCK_SIZE));
        payload.extend_from_slice(&record("size", "513"));
        assert!(payload.len() > BLOCK_SIZE);

        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'x', payload.len() as u64));
        append_payload(&mut bytes, &payload);
        append_block(&mut bytes, &header(b'0', 1));
        append_block(&mut bytes, &data(&[b'a'; BLOCK_SIZE]));
        append_block(&mut bytes, &data(b"b"));
        append_terminator(&mut bytes);

        let frames = collect(bytes, 19);
        assert_eq!(frames.len(), 6);
        let Frame::Pax(pax) = frames[0].as_ref().unwrap() else {
            panic!("expected pax header");
        };
        assert_eq!(pax.kind, PaxKind::Local);
        assert_eq!(pax.payload_size, payload.len() as u64);
        let Frame::Data(first_pax_data) = frames[1].as_ref().unwrap() else {
            panic!("expected first pax data frame");
        };
        assert_eq!(first_pax_data.owner, DataOwner::Pax(PaxKind::Local));
        assert!(first_pax_data.completed_pax_records.is_none());
        let Frame::Data(final_pax_data) = frames[2].as_ref().unwrap() else {
            panic!("expected final pax data frame");
        };
        assert_eq!(final_pax_data.owner, DataOwner::Pax(PaxKind::Local));
        assert_eq!(
            final_pax_data
                .completed_pax_records
                .as_ref()
                .and_then(|records| records.last()),
            Some(&PaxRecord::Size(PaxValue::Value(513)))
        );
        let Frame::Header(header) = frames[3].as_ref().unwrap() else {
            panic!("expected overridden member header");
        };
        assert_eq!(header.declared_size, 1);
        assert_eq!(header.effective_size, Some(513));
        assert_eq!(header.payload_size, 513);
        assert_eq!(header.local_pax_records.len(), 2);
        assert_eq!(
            header.local_pax_records[1],
            PaxRecord::Size(PaxValue::Value(513))
        );
        let Frame::Data(last) = frames[5].as_ref().unwrap() else {
            panic!("expected final member data");
        };
        assert_eq!(last.len, 1);
    }

    #[test]
    fn applies_global_pax_records_overrides_and_preserves_deletions() {
        let mut initial_global = record("comment", "old");
        initial_global.extend_from_slice(&record("size", "2"));
        let replacement_global = record("comment", "new");
        let mut local = record("comment", "local");
        local.extend_from_slice(&record("size", "3"));
        let mut deletion = record("comment", "");
        deletion.extend_from_slice(&record("size", ""));

        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'g', initial_global.len() as u64));
        append_payload(&mut bytes, &initial_global);
        append_block(&mut bytes, &header(b'g', replacement_global.len() as u64));
        append_payload(&mut bytes, &replacement_global);
        append_block(&mut bytes, &header(b'0', 1));
        append_block(&mut bytes, &data(b"ab"));
        append_block(&mut bytes, &header(b'x', local.len() as u64));
        append_payload(&mut bytes, &local);
        append_block(&mut bytes, &header(b'0', 1));
        append_block(&mut bytes, &data(b"abc"));
        append_block(&mut bytes, &header(b'g', deletion.len() as u64));
        append_payload(&mut bytes, &deletion);
        append_block(&mut bytes, &header(b'5', 1));
        append_terminator(&mut bytes);

        let frames = collect(bytes, 31);
        assert!(frames.iter().any(|frame| matches!(
            frame,
            Ok(Frame::Pax(PaxFrame {
                kind: PaxKind::Global,
                ..
            }))
        )));
        assert!(frames.iter().any(|frame| matches!(
            frame,
            Ok(Frame::Data(DataFrame {
                owner: DataOwner::Pax(PaxKind::Global),
                ..
            }))
        )));
        let completed_global_payloads: Vec<&Vec<PaxRecord>> = frames
            .iter()
            .filter_map(|frame| match frame.as_ref().unwrap() {
                Frame::Data(DataFrame {
                    owner: DataOwner::Pax(PaxKind::Global),
                    completed_pax_records: Some(records),
                    ..
                }) => Some(records),
                _ => None,
            })
            .collect();
        assert_eq!(completed_global_payloads.len(), 3);
        assert_eq!(
            completed_global_payloads[2],
            &[
                PaxRecord::Comment(PaxValue::Deleted),
                PaxRecord::Size(PaxValue::Deleted),
            ]
        );
        let headers: Vec<&HeaderFrame> = frames
            .iter()
            .filter_map(|frame| match frame.as_ref().unwrap() {
                Frame::Header(header) => Some(header),
                _ => None,
            })
            .collect();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].effective_size, Some(2));
        assert_eq!(
            headers[0].global_pax_records,
            [
                PaxRecord::Size(PaxValue::Value(2)),
                PaxRecord::Comment(PaxValue::Value("new".to_owned())),
            ]
        );
        assert_eq!(headers[1].effective_size, Some(3));
        assert_eq!(headers[1].local_pax_records, local_records("local", 3));
        assert_eq!(headers[2].effective_size, None);
        assert_eq!(
            headers[2].global_pax_records,
            [
                PaxRecord::Comment(PaxValue::Deleted),
                PaxRecord::Size(PaxValue::Deleted),
            ]
        );
    }

    fn local_records(comment: &str, size: u64) -> Vec<PaxRecord> {
        vec![
            PaxRecord::Comment(PaxValue::Value(comment.to_owned())),
            PaxRecord::Size(PaxValue::Value(size)),
        ]
    }

    #[test]
    fn allows_local_size_deletion_when_a_later_record_restores_size() {
        let mut local = record("size", "");
        local.extend_from_slice(&record("size", "2"));
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'x', local.len() as u64));
        append_payload(&mut bytes, &local);
        append_block(&mut bytes, &header(b'0', 1));
        append_block(&mut bytes, &data(b"ab"));
        append_terminator(&mut bytes);

        let frames = collect(bytes, BLOCK_SIZE);
        let Frame::Header(header) = frames[2].as_ref().unwrap() else {
            panic!("expected member header");
        };
        assert_eq!(header.effective_size, Some(2));
        assert_eq!(
            header.local_pax_records[0],
            PaxRecord::Size(PaxValue::Deleted)
        );
    }

    #[test]
    fn preserves_local_size_deletion_for_payload_free_members() {
        let global = record("size", "7");
        let local = record("size", "");
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'g', global.len() as u64));
        append_payload(&mut bytes, &global);
        append_block(&mut bytes, &header(b'x', local.len() as u64));
        append_payload(&mut bytes, &local);
        append_block(&mut bytes, &header(b'5', 3));
        append_terminator(&mut bytes);

        let frames = collect(bytes, BLOCK_SIZE);
        let Frame::Header(header) = frames[4].as_ref().unwrap() else {
            panic!("expected member header");
        };
        assert_eq!(header.kind, MemberKind::Directory);
        assert_eq!(header.declared_size, 3);
        assert_eq!(header.effective_size, None);
        assert_eq!(header.payload_size, 0);
        assert_eq!(
            header.global_pax_records[0],
            PaxRecord::Size(PaxValue::Value(7))
        );
        assert_eq!(
            header.local_pax_records[0],
            PaxRecord::Size(PaxValue::Deleted)
        );
    }

    #[test]
    fn rejects_deleted_size_when_member_payload_cannot_be_framed() {
        let local = record("size", "");
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'x', local.len() as u64));
        append_payload(&mut bytes, &local);
        append_block(&mut bytes, &header(b'0', 0));

        assert!(matches!(
            last_error_inner(&collect(bytes, BLOCK_SIZE)),
            FrameErrorInner::IndeterminateMemberSize {
                kind: MemberKind::Regular
            }
        ));
    }

    #[test]
    fn rejects_global_size_deletion_when_member_payload_cannot_be_framed() {
        let global = record("size", "");
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'g', global.len() as u64));
        append_payload(&mut bytes, &global);
        append_block(&mut bytes, &header(b'0', 0));

        assert!(matches!(
            last_error_inner(&collect(bytes, BLOCK_SIZE)),
            FrameErrorInner::IndeterminateMemberSize {
                kind: MemberKind::Regular
            }
        ));
    }

    #[test]
    fn allows_local_size_to_restore_an_active_global_deletion() {
        let global = record("size", "");
        let local = record("size", "2");
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'g', global.len() as u64));
        append_payload(&mut bytes, &global);
        append_block(&mut bytes, &header(b'x', local.len() as u64));
        append_payload(&mut bytes, &local);
        append_block(&mut bytes, &header(b'0', 1));
        append_block(&mut bytes, &data(b"ab"));
        append_terminator(&mut bytes);

        let frames = collect(bytes, BLOCK_SIZE);
        let Frame::Header(header) = frames[4].as_ref().unwrap() else {
            panic!("expected member header");
        };
        assert_eq!(header.effective_size, Some(2));
        assert_eq!(
            header.global_pax_records[0],
            PaxRecord::Size(PaxValue::Deleted)
        );
        assert_eq!(
            header.local_pax_records[0],
            PaxRecord::Size(PaxValue::Value(2))
        );
    }

    #[test]
    fn accepts_pax_linkdata() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'1', 3));
        append_block(&mut bytes, &data(b"abc"));
        append_terminator(&mut bytes);

        let frames = collect(bytes, BLOCK_SIZE);
        let Frame::Header(header) = frames[0].as_ref().unwrap() else {
            panic!("expected hard-link header");
        };
        assert_eq!(header.kind, MemberKind::HardLink);
        assert_eq!(header.payload_size, 3);
        let Frame::Data(data) = frames[1].as_ref().unwrap() else {
            panic!("expected link data");
        };
        assert_eq!(data.len, 3);
    }

    #[test]
    fn zero_data_block_is_not_a_terminator() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'0', BLOCK_SIZE as u64));
        append_block(&mut bytes, &[0; BLOCK_SIZE]);
        append_terminator(&mut bytes);

        let frames = collect(bytes, BLOCK_SIZE);
        assert_eq!(frames.len(), 2);
        assert!(matches!(frames[1], Ok(Frame::Data(_))));
    }

    #[test]
    fn zero_filled_block_inside_pax_payload_is_data() {
        let payload = record("comment", &"\0".repeat(BLOCK_SIZE * 3));
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'x', payload.len() as u64));
        append_payload(&mut bytes, &payload);
        append_block(&mut bytes, &header(b'0', 0));
        append_terminator(&mut bytes);

        let frames = collect(bytes, BLOCK_SIZE);
        assert!(frames.iter().any(|frame| matches!(
            frame,
            Ok(Frame::Data(DataFrame {
                block,
                owner: DataOwner::Pax(PaxKind::Local),
                ..
            })) if is_zero_block(block)
        )));
    }

    #[test]
    fn frames_gnu_long_metadata_and_base256_payloads() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &gnu_base256_header(b'L', 513));
        append_block(&mut bytes, &data(&[b'n'; BLOCK_SIZE]));
        append_block(&mut bytes, &data(b"\0"));
        append_block(&mut bytes, &gnu_header(b'K', 5));
        append_block(&mut bytes, &data(b"link\0"));
        append_block(&mut bytes, &gnu_header(b'2', 0));
        append_terminator(&mut bytes);

        let frames = collect(bytes, 13);
        assert_eq!(frames.len(), 6);
        assert!(matches!(
            frames[0].as_ref().unwrap(),
            Frame::Gnu(GnuFrame {
                kind: GnuKind::LongName,
                payload_size: 513,
                ..
            })
        ));
        let Frame::Data(final_name) = frames[2].as_ref().unwrap() else {
            panic!("expected long-name payload");
        };
        assert_eq!(final_name.owner, DataOwner::Gnu(GnuKind::LongName));
        assert_eq!(final_name.len, 1);
        assert!(final_name.completed_pax_records.is_none());
        assert!(matches!(
            frames[3].as_ref().unwrap(),
            Frame::Gnu(GnuFrame {
                kind: GnuKind::LongLink,
                ..
            })
        ));
        let Frame::Header(header) = frames[5].as_ref().unwrap() else {
            panic!("expected GNU member header");
        };
        assert_eq!(header.kind, MemberKind::SymbolicLink);
        assert!(header.global_pax_records.is_empty());
        assert!(header.local_pax_records.is_empty());
    }

    #[test]
    fn rejects_header_format_and_type_errors() {
        let mut bad_magic = header(b'0', 0);
        bad_magic[IDENTITY_RANGE.start] = b'g';
        assert!(matches!(
            last_error_inner(&collect(bad_magic.to_vec(), BLOCK_SIZE)),
            FrameErrorInner::InvalidIdentity { .. }
        ));

        let mut bad_version = header(b'0', 0);
        bad_version[IDENTITY_RANGE.end - 2..IDENTITY_RANGE.end].copy_from_slice(b"  ");
        assert!(matches!(
            last_error_inner(&collect(bad_version.to_vec(), BLOCK_SIZE)),
            FrameErrorInner::InvalidIdentity { .. }
        ));

        let mut bad_checksum = header(b'0', 0);
        bad_checksum[0] = b'X';
        assert!(matches!(
            last_error_inner(&collect(bad_checksum.to_vec(), BLOCK_SIZE)),
            FrameErrorInner::InvalidChecksum { .. }
        ));

        let mut bad_size = header(b'0', 0);
        bad_size[SIZE_RANGE].copy_from_slice(b"00000000008\0");
        set_checksum(&mut bad_size);
        assert!(matches!(
            last_error_inner(&collect(bad_size.to_vec(), BLOCK_SIZE)),
            FrameErrorInner::InvalidSize { .. }
        ));

        let mut base256_size = header(b'0', 0);
        base256_size[SIZE_RANGE.start] = 0x80;
        set_checksum(&mut base256_size);
        assert!(matches!(
            last_error_inner(&collect(base256_size.to_vec(), BLOCK_SIZE)),
            FrameErrorInner::InvalidSize { .. }
        ));

        assert!(matches!(
            last_error_inner(&collect(header(b'X', 0).to_vec(), BLOCK_SIZE)),
            FrameErrorInner::UnsupportedTypeflag { typeflag: b'X' }
        ));
        assert!(matches!(
            last_error_inner(&collect(header(b'L', 0).to_vec(), BLOCK_SIZE)),
            FrameErrorInner::UnsupportedTypeflag { typeflag: b'L' }
        ));
    }

    #[test]
    fn rejects_invalid_pax_sequences() {
        assert!(matches!(
            last_error_inner(&collect(header(b'x', 0).to_vec(), BLOCK_SIZE)),
            FrameErrorInner::InvalidPaxRecords { .. }
        ));

        let valid = record("path", "name");
        let mut consecutive = Vec::new();
        append_block(&mut consecutive, &header(b'x', valid.len() as u64));
        append_payload(&mut consecutive, &valid);
        append_block(&mut consecutive, &header(b'x', valid.len() as u64));
        assert!(matches!(
            last_error_inner(&collect(consecutive, BLOCK_SIZE)),
            FrameErrorInner::UnexpectedOrder { .. }
        ));

        let mut missing_member = Vec::new();
        append_block(&mut missing_member, &header(b'x', valid.len() as u64));
        append_payload(&mut missing_member, &valid);
        assert!(matches!(
            last_error_inner(&collect(missing_member, BLOCK_SIZE)),
            FrameErrorInner::UnexpectedEof { .. }
        ));
    }

    #[test]
    fn preserves_pax_parse_error_positions_in_stream() {
        let invalid = record("size", "bad");
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'0', 0));
        append_block(&mut bytes, &header(b'x', invalid.len() as u64));
        append_payload(&mut bytes, &invalid);

        let frames = collect(bytes, BLOCK_SIZE);
        assert!(matches!(
            frames.last(),
            Some(Err(FrameError {
                position,
                inner: FrameErrorInner::InvalidPaxInteger { .. },
            })) if *position == BLOCK_SIZE as u64
        ));
    }

    #[test]
    fn rejects_unsupported_pax_charsets() {
        const UTF8_HDRCHARSET: &str = "ISO-IR 10646 2000 UTF-8";

        for typeflag in [b'x', b'g'] {
            let records = record("hdrcharset", "BINARY");
            let mut bytes = Vec::new();
            append_block(&mut bytes, &header(typeflag, records.len() as u64));
            append_payload(&mut bytes, &records);
            assert!(matches!(
                last_error_inner(&collect(bytes, BLOCK_SIZE)),
                FrameErrorInner::UnsupportedPaxCharset { value } if value == "BINARY"
            ));
        }

        let mut records = record("hdrcharset", "BINARY");
        records.extend_from_slice(&record("hdrcharset", UTF8_HDRCHARSET));
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'x', records.len() as u64));
        append_payload(&mut bytes, &records);
        assert!(matches!(
            last_error_inner(&collect(bytes, BLOCK_SIZE)),
            FrameErrorInner::UnsupportedPaxCharset { value } if value == "BINARY"
        ));
    }

    #[test]
    fn rejects_invalid_gnu_sequences_and_sizes() {
        let mut duplicate = Vec::new();
        append_block(&mut duplicate, &gnu_header(b'L', 0));
        append_block(&mut duplicate, &gnu_header(b'L', 0));
        assert!(matches!(
            last_error_inner(&collect(duplicate, BLOCK_SIZE)),
            FrameErrorInner::UnexpectedOrder { .. }
        ));

        let mut long_link_for_regular = Vec::new();
        append_block(&mut long_link_for_regular, &gnu_header(b'K', 0));
        append_block(&mut long_link_for_regular, &gnu_header(b'0', 0));
        assert!(matches!(
            last_error_inner(&collect(long_link_for_regular, BLOCK_SIZE)),
            FrameErrorInner::UnexpectedOrder { .. }
        ));

        let mut dangling = Vec::new();
        append_block(&mut dangling, &gnu_header(b'L', 0));
        append_terminator(&mut dangling);
        assert!(matches!(
            last_error_inner(&collect(dangling, BLOCK_SIZE)),
            FrameErrorInner::UnexpectedOrder { .. }
        ));

        assert!(matches!(
            last_error_inner(&collect(gnu_header(b'S', 0).to_vec(), BLOCK_SIZE)),
            FrameErrorInner::UnsupportedTypeflag { typeflag: b'S' }
        ));

        let mut negative_size = gnu_header(b'0', 0);
        negative_size[SIZE_RANGE].fill(0xff);
        set_checksum(&mut negative_size);
        assert!(matches!(
            last_error_inner(&collect(negative_size.to_vec(), BLOCK_SIZE)),
            FrameErrorInner::InvalidSize { .. }
        ));
    }

    #[test]
    fn detects_one_archive_family_and_rejects_mixing() {
        let mut posix_then_gnu = Vec::new();
        append_block(&mut posix_then_gnu, &header(b'0', 0));
        append_block(&mut posix_then_gnu, &gnu_header(b'0', 0));
        assert!(matches!(
            last_error_inner(&collect(posix_then_gnu, BLOCK_SIZE)),
            FrameErrorInner::FormatMismatch {
                expected: ArchiveFormat::PosixPax,
                found: ArchiveFormat::Gnu,
            }
        ));

        let mut gnu_then_posix = Vec::new();
        append_block(&mut gnu_then_posix, &gnu_header(b'0', 0));
        append_block(&mut gnu_then_posix, &header(b'0', 0));
        assert!(matches!(
            last_error_inner(&collect(gnu_then_posix, BLOCK_SIZE)),
            FrameErrorInner::FormatMismatch {
                expected: ArchiveFormat::Gnu,
                found: ArchiveFormat::PosixPax,
            }
        ));

        assert!(matches!(
            last_error_inner(&collect(gnu_header(b'x', 0).to_vec(), BLOCK_SIZE)),
            FrameErrorInner::UnsupportedTypeflag { typeflag: b'x' }
        ));
        assert!(matches!(
            last_error_inner(&collect(gnu_header(b'g', 0).to_vec(), BLOCK_SIZE)),
            FrameErrorInner::UnsupportedTypeflag { typeflag: b'g' }
        ));

        let mut empty = Vec::new();
        append_terminator(&mut empty);
        let mut stream = TarStream::new(ChunkedReader::new(empty, BLOCK_SIZE));
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(None)
        ));
        assert_eq!(stream.format(), None);
    }

    #[test]
    fn rejects_truncation_and_invalid_termination() {
        assert!(matches!(
            last_error_inner(&collect(vec![0; 3], 1)),
            FrameErrorInner::IncompleteBlock { read: 3 }
        ));

        let mut payload_truncated = Vec::new();
        append_block(&mut payload_truncated, &header(b'0', 1));
        assert!(matches!(
            last_error_inner(&collect(payload_truncated, BLOCK_SIZE)),
            FrameErrorInner::TruncatedPayload {
                owner: DataOwner::Member,
                ..
            }
        ));

        let mut pax_payload_truncated = Vec::new();
        append_block(&mut pax_payload_truncated, &header(b'x', 513));
        append_block(&mut pax_payload_truncated, &data(b"11 path=x\n"));
        assert!(matches!(
            last_error_inner(&collect(pax_payload_truncated, BLOCK_SIZE)),
            FrameErrorInner::TruncatedPayload {
                owner: DataOwner::Pax(PaxKind::Local),
                ..
            }
        ));

        let mut missing_second_zero = Vec::new();
        append_block(&mut missing_second_zero, &header(b'0', 0));
        append_block(&mut missing_second_zero, &[0; BLOCK_SIZE]);
        assert!(matches!(
            last_error_inner(&collect(missing_second_zero, BLOCK_SIZE)),
            FrameErrorInner::MissingEndMarker
        ));

        let mut bad_second_zero = Vec::new();
        append_block(&mut bad_second_zero, &header(b'0', 0));
        append_block(&mut bad_second_zero, &[0; BLOCK_SIZE]);
        append_block(&mut bad_second_zero, &header(b'0', 0));
        assert!(matches!(
            last_error_inner(&collect(bad_second_zero, BLOCK_SIZE)),
            FrameErrorInner::InvalidEndMarker
        ));
    }

    #[test]
    fn stream_is_fused_after_first_error() {
        let mut stream = TarStream::new(ChunkedReader::new(header(b'L', 0).to_vec(), BLOCK_SIZE));
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(Some(Err(FrameError {
                position: 0,
                inner: FrameErrorInner::UnsupportedTypeflag { typeflag: b'L' },
            })))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn logical_reader_groups_pax_metadata_and_streams_member_payload() {
        let global = record("comment", "global");
        let mut local = record("path", "renamed");
        local.extend_from_slice(&record("size", "513"));
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'g', global.len() as u64));
        append_payload(&mut bytes, &global);
        append_block(&mut bytes, &header(b'x', local.len() as u64));
        append_payload(&mut bytes, &local);
        append_block(&mut bytes, &header(b'0', 1));
        append_block(&mut bytes, &data(&[b'a'; BLOCK_SIZE]));
        append_block(&mut bytes, &data(b"b"));
        append_terminator(&mut bytes);

        let result: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, 17));
            let Some(LogicalFrame::GlobalPax(global_header)) = reader.next_frame().await? else {
                panic!("expected global pax header");
            };
            assert_eq!(global_header.kind, PaxKind::Global);
            assert_eq!(
                global_header.records,
                [PaxRecord::Comment(PaxValue::Value("global".to_owned()))]
            );

            {
                let Some(LogicalFrame::Member(mut member)) = reader.next_frame().await? else {
                    panic!("expected logical member");
                };
                assert_eq!(member.header.effective_size, Some(513));
                let MemberExtensions::PosixPax {
                    global_records,
                    local: Some(local_header),
                } = &member.extensions
                else {
                    panic!("expected local pax member metadata");
                };
                assert_eq!(global_records, &global_header.records);
                assert_eq!(
                    local_header.records.last(),
                    Some(&PaxRecord::Size(PaxValue::Value(513)))
                );
                let Some(first) = member.payload.next_block().await? else {
                    panic!("expected first member payload block");
                };
                let Some(last) = member.payload.next_block().await? else {
                    panic!("expected last member payload block");
                };
                assert_eq!(first.len, BLOCK_SIZE);
                assert_eq!(last.len, 1);
                assert!(member.payload.next_block().await?.is_none());
            }
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });
        assert!(result.is_ok());
    }

    #[test]
    fn logical_reader_groups_gnu_metadata_with_its_member() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &gnu_header(b'L', 5));
        append_block(&mut bytes, &data(b"name\0"));
        append_block(&mut bytes, &gnu_header(b'K', 5));
        append_block(&mut bytes, &data(b"link\0"));
        append_block(&mut bytes, &gnu_header(b'2', 0));
        append_terminator(&mut bytes);

        let result: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let Some(LogicalFrame::Member(mut member)) = reader.next_frame().await? else {
                panic!("expected GNU member");
            };
            let MemberExtensions::Gnu {
                long_name: Some(long_name),
                long_link: Some(long_link),
            } = &member.extensions
            else {
                panic!("expected GNU extensions");
            };
            assert_eq!(long_name.payload, b"name\0");
            assert_eq!(long_link.payload, b"link\0");
            assert!(member.payload.next_block().await?.is_none());
            Ok(())
        });
        assert!(result.is_ok());
    }

    #[test]
    fn logical_reader_handles_empty_archives_and_rejects_dangling_metadata() {
        let mut empty = Vec::new();
        append_terminator(&mut empty);
        let empty_result: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(empty, BLOCK_SIZE));
            assert!(reader.next_frame().await?.is_none());
            assert_eq!(reader.format(), None);
            Ok(())
        });
        assert!(empty_result.is_ok());

        for header in [
            header(b'x', record("path", "name").len() as u64),
            gnu_header(b'L', 0),
        ] {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &header);
            if header[TYPEFLAG_OFFSET] == b'x' {
                append_payload(&mut bytes, &record("path", "name"));
            }
            let error: Result<(), FrameError> = ready(async {
                let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
                reader.next_frame().await.map(|_| ())
            });
            assert!(matches!(
                error,
                Err(FrameError {
                    inner: FrameErrorInner::UnexpectedEof { .. },
                    ..
                })
            ));
        }
    }

    #[test]
    fn logical_reader_skips_unread_payload_before_advancing() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'0', 513));
        append_block(&mut bytes, &data(&[b'a'; BLOCK_SIZE]));
        append_block(&mut bytes, &data(b"b"));
        append_block(&mut bytes, &header(b'0', 0));
        append_terminator(&mut bytes);

        let result: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            {
                let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                    panic!("expected first member");
                };
                member.payload.skip().await?;
            }
            let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                panic!("expected second member");
            };
            assert_eq!(member.header.payload_size, 0);
            drop(member);
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });
        assert!(result.is_ok());

        let mut auto_bytes = Vec::new();
        append_block(&mut auto_bytes, &header(b'0', 1));
        append_block(&mut auto_bytes, &data(b"a"));
        append_block(&mut auto_bytes, &header(b'0', 0));
        append_terminator(&mut auto_bytes);
        let auto_result: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(auto_bytes, BLOCK_SIZE));
            let Some(LogicalFrame::Member(first)) = reader.next_frame().await? else {
                panic!("expected first member");
            };
            drop(first);
            assert!(matches!(
                reader.next_frame().await?,
                Some(LogicalFrame::Member(_))
            ));
            Ok(())
        });
        assert!(auto_result.is_ok());
    }

    #[test]
    fn logical_reader_reports_truncated_payload_when_read_or_skipped() {
        let bytes = header(b'0', 1).to_vec();
        let read_error = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes.clone(), BLOCK_SIZE));
            let Ok(Some(LogicalFrame::Member(mut member))) = reader.next_frame().await else {
                panic!("expected member");
            };
            member.payload.next_block().await
        });
        assert!(matches!(
            read_error,
            Err(FrameError {
                inner: FrameErrorInner::TruncatedPayload {
                    owner: DataOwner::Member,
                    ..
                },
                ..
            })
        ));

        let skip_error: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let Ok(Some(LogicalFrame::Member(member))) = reader.next_frame().await else {
                panic!("expected member");
            };
            drop(member);
            reader.next_frame().await.map(|_| ())
        });
        assert!(matches!(
            skip_error,
            Err(FrameError {
                inner: FrameErrorInner::TruncatedPayload {
                    owner: DataOwner::Member,
                    ..
                },
                ..
            })
        ));
    }
}
