//! Low level framing of tar streams.
//!
//! This crate provides the lossless block-level [`physical`] framing API and
//! the assembled member-level [`logical`] reader API.
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

pub mod logical;
mod pax;
pub mod physical;
#[cfg(test)]
mod test_support;

use pax::{
    PaxSize, apply_global as apply_global_pax_records, parse_records as parse_pax_records,
    size as pax_size,
};
use physical::{DataFrame, DataOwner, Frame, GnuFrame, HeaderFrame, PaxFrame, TarStream};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_stream::Stream;

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

    pub(crate) fn position(&self) -> u64 {
        self.position
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
