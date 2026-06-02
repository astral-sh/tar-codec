//! Lossless, block-oriented tar streaming.
//!
//! This API emits one frame for each accepted non-terminator physical
//! tar block and preserves each source block verbatim.

use std::{
    borrow::Cow,
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};
use tokio_stream::Stream;

use crate::{
    ArchiveFormat, BLOCK_SIZE, Block, FrameError, FrameErrorInner, GnuKind, MemberKind, PaxKind,
    PaxRecord, PaxValue,
    header::{
        CHECKSUM_RANGE, GNU_IDENTITY, IDENTITY_RANGE, LINK_NAME_RANGE, MODE_RANGE, NAME_RANGE,
        POSIX_IDENTITY, PREFIX_RANGE, SIZE_RANGE, TYPEFLAG_OFFSET, checksum, parse_octal,
    },
    pax::{
        apply_global as apply_global_pax_records, hdrcharset as pax_hdrcharset,
        parse_records as parse_pax_records, size as pax_size,
    },
};

type PositionedBlock = (u64, Block);

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
    pub block: Block,
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
    pub block: Block,
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
    pub block: Block,
    /// The selected archive family of this member header.
    pub format: ArchiveFormat,
    /// The member type identified by the header.
    pub kind: MemberKind,
    /// The size encoded directly in the member header field.
    pub declared_size: u64,
    /// The size after applying applicable pax `size` records.
    pub effective_size: u64,
    /// The number of payload bytes for which data frames will be emitted.
    pub payload_size: u64,
    /// Effective global pax records active for this member, including deletions.
    pub global_pax_records: Vec<PaxRecord>,
    /// Parsed local pax records that apply to this member, in input order.
    pub local_pax_records: Vec<PaxRecord>,
}

impl HeaderFrame {
    /// Decodes the ordinary header's numeric mode according to its archive family.
    pub fn mode(&self) -> Result<u64, FrameError> {
        let bytes: [u8; 8] = self.block[MODE_RANGE]
            .try_into()
            .expect("fixed header range");
        parse_number(self.format, &bytes).ok_or_else(|| {
            FrameError::at(self.position, FrameErrorInner::InvalidMode { found: bytes })
        })
    }

    pub(crate) fn header_path(&self) -> Cow<'_, [u8]> {
        let name = trim_nul(&self.block[NAME_RANGE]);
        if self.format == ArchiveFormat::Gnu {
            return Cow::Borrowed(name);
        }
        let prefix = trim_nul(&self.block[PREFIX_RANGE]);
        if prefix.is_empty() {
            Cow::Borrowed(name)
        } else if name.is_empty() {
            Cow::Borrowed(prefix)
        } else {
            let mut path = Vec::with_capacity(prefix.len() + 1 + name.len());
            path.extend_from_slice(prefix);
            path.push(b'/');
            path.extend_from_slice(name);
            Cow::Owned(path)
        }
    }

    pub(crate) fn link_name(&self) -> &[u8] {
        trim_nul(&self.block[LINK_NAME_RANGE])
    }
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
    pub block: Block,
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

/// The parser phase required before the next physical frame can be emitted.
#[derive(Debug)]
pub(super) enum State {
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
    AwaitingUstarHeader { records: Vec<PaxRecord> },
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
pub(super) struct PendingGnu {
    pub(super) long_name: bool,
    pub(super) long_link: bool,
}

/// A strict stream of POSIX-pax or GNU frames sourced from an underlying reader.
pub struct TarStream<R> {
    pub(super) position: u64,
    pub(super) inner: R,
    pub(super) block: Block,
    pub(super) block_len: usize,
    pub(super) format: Option<ArchiveFormat>,
    pub(super) global_pax_records: Vec<PaxRecord>,
    pub(super) state: State,
}

impl<R> TarStream<R> {
    /// Creates a new [`TarStream`] from the given reader.
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
    /// Reads aligned ordinary-member payload blocks directly into `buffer`.
    ///
    /// This internal path preserves exact physical-block completion checks
    /// while avoiding lossless [`Frame`] construction for chunk consumers.
    pub(crate) async fn read_member_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<usize, FrameError> {
        buffer.clear();
        let remaining = match &self.state {
            State::ReadingMember { remaining } => *remaining,
            _ => {
                self.state = State::Failed;
                return Err(FrameError::at(
                    self.position,
                    FrameErrorInner::UnexpectedOrder {
                        expected: "ordinary member payload",
                        found: "parser state without member payload",
                    },
                ));
            }
        };
        if self.block_len != 0 {
            self.state = State::Failed;
            return Err(FrameError::at(
                self.position,
                FrameErrorInner::UnexpectedOrder {
                    expected: "aligned ordinary member payload",
                    found: "partially buffered physical block",
                },
            ));
        }

        let target_blocks = target_len.max(BLOCK_SIZE).div_ceil(BLOCK_SIZE);
        let target_blocks = u64::try_from(target_blocks).map_err(|_| {
            FrameError::at(
                self.position,
                FrameErrorInner::ArithmeticOverflow {
                    context: "member payload chunk block count",
                },
            )
        })?;
        let remaining_blocks = remaining.div_ceil(BLOCK_SIZE as u64);
        let physical_len = target_blocks
            .min(remaining_blocks)
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or_else(|| {
                FrameError::at(
                    self.position,
                    FrameErrorInner::ArithmeticOverflow {
                        context: "member payload chunk physical length",
                    },
                )
            })?;
        let meaningful_len = remaining.min(physical_len);
        let physical_len = usize::try_from(physical_len).map_err(|_| {
            FrameError::at(
                self.position,
                FrameErrorInner::ArithmeticOverflow {
                    context: "member payload chunk physical length",
                },
            )
        })?;
        let meaningful_len = usize::try_from(meaningful_len).map_err(|_| {
            FrameError::at(
                self.position,
                FrameErrorInner::ArithmeticOverflow {
                    context: "member payload chunk meaningful length",
                },
            )
        })?;

        buffer.resize(physical_len, 0);
        let start_position = self.position;
        let mut filled = 0;
        while filled < physical_len {
            let read = match poll_fn(|context| {
                let mut read_buffer = ReadBuf::new(&mut buffer[filled..]);
                match Pin::new(&mut self.inner).poll_read(context, &mut read_buffer) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buffer.filled().len())),
                    Poll::Ready(Err(source)) => Poll::Ready(Err(source)),
                }
            })
            .await
            {
                Ok(read) => read,
                Err(source) => {
                    self.state = State::Failed;
                    let error_position = checked_position(start_position, filled)?;
                    self.position =
                        checked_position(start_position, completed_block_bytes(filled))?;
                    return Err(FrameError::at(
                        error_position,
                        FrameErrorInner::Io { source },
                    ));
                }
            };
            if read == 0 {
                self.state = State::Failed;
                let partial_len = filled % BLOCK_SIZE;
                let completed_len = filled - partial_len;
                self.position = checked_position(start_position, completed_len)?;
                if partial_len != 0 {
                    return Err(FrameError::at(
                        self.position,
                        FrameErrorInner::IncompleteBlock { read: partial_len },
                    ));
                }
                let completed_len = u64::try_from(completed_len).map_err(|_| {
                    FrameError::at(
                        self.position,
                        FrameErrorInner::ArithmeticOverflow {
                            context: "completed member payload chunk length",
                        },
                    )
                })?;
                return Err(FrameError::at(
                    self.position,
                    FrameErrorInner::TruncatedPayload {
                        owner: DataOwner::Member,
                        remaining: remaining - remaining.min(completed_len),
                    },
                ));
            }
            filled += read;
        }

        self.position = checked_position(start_position, physical_len).inspect_err(|_| {
            self.state = State::Failed;
        })?;
        let remaining = remaining
            .checked_sub(meaningful_len as u64)
            .ok_or_else(|| {
                self.state = State::Failed;
                FrameError::at(
                    start_position,
                    FrameErrorInner::ArithmeticOverflow {
                        context: "remaining member payload length",
                    },
                )
            })?;
        self.state = member_payload_state(remaining);
        buffer.truncate(meaningful_len);
        Ok(meaningful_len)
    }

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

    fn process_block(&mut self, position: u64, block: Block) -> Result<Option<Frame>, FrameError> {
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
                    let records = parse_pax_records(
                        header_position,
                        &payload,
                        pax_hdrcharset(&self.global_pax_records),
                    )?;
                    match kind {
                        PaxKind::Local => {
                            self.state = State::AwaitingUstarHeader {
                                records: records.clone(),
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
            State::AwaitingUstarHeader { records } => {
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
                self.process_ustar_header(position, block, parsed, records)
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
                self.state = member_payload_state(remaining);
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
        block: Block,
    ) -> Result<Frame, FrameError> {
        let parsed = self.parse_format_checked_header(position, &block)?;
        match parsed.format {
            ArchiveFormat::Pax => self.process_posix_boundary_header(position, block, parsed),
            ArchiveFormat::Gnu => {
                self.process_gnu_header(position, block, parsed, PendingGnu::default())
            }
        }
    }

    /// Parses a header and enforces the archive's single selected format.
    ///
    /// The first non-terminator header selects the format; later headers must
    /// decode as valid headers of that same family.
    fn parse_format_checked_header(
        &mut self,
        position: u64,
        block: &Block,
    ) -> Result<ParsedHeader, FrameError> {
        let parsed = ParsedHeader::try_from_framed(position, block)?;
        if let Some(expected) = self.format
            && parsed.format != expected
        {
            return Err(FrameError::at(
                position,
                FrameErrorInner::FormatMismatch {
                    expected,
                    found: parsed.format,
                },
            ));
        }
        self.format.get_or_insert(parsed.format);
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
        block: Block,
        parsed: ParsedHeader,
    ) -> Result<Frame, FrameError> {
        match parsed.typeflag {
            b'x' => self.process_pax_header(position, block, parsed.size, PaxKind::Local),
            b'g' => self.process_pax_header(position, block, parsed.size, PaxKind::Global),
            _ => self.process_ustar_header(position, block, parsed, Vec::new()),
        }
    }

    /// Emits a pax extension header and enters its payload-reading state.
    ///
    /// This is reached only from the POSIX boundary state, before any local
    /// pax records require an ordinary member header.
    fn process_pax_header(
        &mut self,
        position: u64,
        block: Block,
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
        block: Block,
        parsed: ParsedHeader,
        local_pax_records: Vec<PaxRecord>,
    ) -> Result<Frame, FrameError> {
        let kind = MemberKind::try_from_framed(position, parsed.typeflag)?;
        let effective_size = pax_size(&local_pax_records)
            .or_else(|| pax_size(&self.global_pax_records))
            .map_or(Ok(parsed.size), |size| match size {
                PaxValue::Value(size) => Ok(*size),
                PaxValue::Deleted => Err(FrameError::at(
                    position,
                    FrameErrorInner::DeletedPaxMetadata { keyword: "size" },
                )),
            })?;
        let payload_size = posix_payload_size(position, kind, effective_size)?;
        self.state = member_payload_state(payload_size);
        Ok(Frame::Header(HeaderFrame {
            position,
            block,
            format: ArchiveFormat::Pax,
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
        block: Block,
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

        let kind = MemberKind::try_from_framed(position, parsed.typeflag)?;
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
        self.state = member_payload_state(payload_size);
        Ok(Frame::Header(HeaderFrame {
            position,
            block,
            format: ArchiveFormat::Gnu,
            kind,
            declared_size: parsed.size,
            effective_size: parsed.size,
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
    format: ArchiveFormat,
    typeflag: u8,
    size: u64,
}

/// Converts raw tar input into a typed value while retaining source position
/// for any framing error produced by the conversion.
trait TryFromFramed<T>: Sized {
    fn try_from_framed(position: u64, source: T) -> Result<Self, FrameError>;
}

fn is_zero_block(block: &Block) -> bool {
    block.iter().all(|byte| *byte == 0)
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..end]
}

fn member_payload_state(remaining: u64) -> State {
    if remaining == 0 {
        State::AwaitingHeader
    } else {
        State::ReadingMember { remaining }
    }
}

fn completed_block_bytes(len: usize) -> usize {
    len - len % BLOCK_SIZE
}

fn checked_position(position: u64, len: usize) -> Result<u64, FrameError> {
    let len = u64::try_from(len).map_err(|_| {
        FrameError::at(
            position,
            FrameErrorInner::ArithmeticOverflow {
                context: "stream position",
            },
        )
    })?;
    position.checked_add(len).ok_or_else(|| {
        FrameError::at(
            position,
            FrameErrorInner::ArithmeticOverflow {
                context: "stream position",
            },
        )
    })
}

impl TryFromFramed<&Block> for ParsedHeader {
    fn try_from_framed(position: u64, block: &Block) -> Result<Self, FrameError> {
        let format = match &block[IDENTITY_RANGE] {
            identity if identity == POSIX_IDENTITY => ArchiveFormat::Pax,
            identity if identity == GNU_IDENTITY => ArchiveFormat::Gnu,
            identity => {
                return Err(FrameError::at(
                    position,
                    FrameErrorInner::InvalidIdentity {
                        found: identity.try_into().expect("fixed header range"),
                    },
                ));
            }
        };

        let actual_checksum = checksum(block);
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
        let size = parse_number(format, &size_bytes).ok_or_else(|| {
            FrameError::at(position, FrameErrorInner::InvalidSize { found: size_bytes })
        })?;

        Ok(Self {
            format,
            typeflag: block[TYPEFLAG_OFFSET],
            size,
        })
    }
}

pub(crate) fn parse_number(format: ArchiveFormat, bytes: &[u8]) -> Option<u64> {
    match format {
        ArchiveFormat::Pax => parse_octal(bytes),
        ArchiveFormat::Gnu => parse_gnu_number(bytes),
    }
}

fn parse_gnu_number(bytes: &[u8]) -> Option<u64> {
    if bytes.first() != Some(&0x80) {
        return parse_octal(bytes);
    }
    bytes[1..].iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(256)?.checked_add(u64::from(*byte))
    })
}

impl TryFromFramed<u8> for MemberKind {
    fn try_from_framed(position: u64, typeflag: u8) -> Result<Self, FrameError> {
        match typeflag {
            0 | b'0' => Ok(Self::Regular),
            b'1' => Ok(Self::HardLink),
            b'2' => Ok(Self::SymbolicLink),
            b'3' => Ok(Self::CharacterDevice),
            b'4' => Ok(Self::BlockDevice),
            b'5' => Ok(Self::Directory),
            b'6' => Ok(Self::Fifo),
            b'7' => Ok(Self::Contiguous),
            _ => Err(FrameError::at(
                position,
                FrameErrorInner::UnsupportedTypeflag { typeflag },
            )),
        }
    }
}

fn posix_payload_size(position: u64, kind: MemberKind, size: u64) -> Result<u64, FrameError> {
    match kind {
        MemberKind::Regular | MemberKind::HardLink | MemberKind::Contiguous => Ok(size),
        MemberKind::SymbolicLink => {
            if size != 0 {
                return Err(FrameError::at(
                    position,
                    FrameErrorInner::InvalidMemberSize { kind, size },
                ));
            }
            Ok(0)
        }
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
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio_stream::{Stream, StreamExt};

    use super::*;
    use crate::{
        ArchiveFormat, FrameError, FrameErrorInner, HdrCharset, PaxString, PaxValue,
        test_support::{
            ChunkedReader, append_block, append_gnu, append_payload, append_posix,
            append_terminator, gnu_base256_header, gnu_header, header, ready, record, set_checksum,
        },
    };

    fn collect(bytes: Vec<u8>, max_chunk: usize) -> Vec<Result<Frame, FrameError>> {
        ready(TarStream::new(ChunkedReader::new(bytes, max_chunk)).collect())
    }

    fn header_frame(frames: &[Result<Frame, FrameError>], index: usize) -> &HeaderFrame {
        let Ok(Frame::Header(frame)) = &frames[index] else {
            panic!("expected header frame");
        };
        frame
    }

    fn data_frame(frames: &[Result<Frame, FrameError>], index: usize) -> &DataFrame {
        let Ok(Frame::Data(frame)) = &frames[index] else {
            panic!("expected data frame");
        };
        frame
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

    #[derive(Clone, Copy)]
    enum ExpectedHeaderError {
        InvalidIdentity,
        InvalidChecksum,
        InvalidSize,
        UnsupportedTypeflag(u8),
    }

    impl ExpectedHeaderError {
        fn matches(self, error: &FrameErrorInner) -> bool {
            match (self, error) {
                (Self::InvalidIdentity, FrameErrorInner::InvalidIdentity { .. })
                | (Self::InvalidChecksum, FrameErrorInner::InvalidChecksum { .. })
                | (Self::InvalidSize, FrameErrorInner::InvalidSize { .. }) => true,
                (
                    Self::UnsupportedTypeflag(typeflag),
                    FrameErrorInner::UnsupportedTypeflag { typeflag: found },
                ) => typeflag == *found,
                _ => false,
            }
        }
    }

    fn invalid_header_cases() -> Vec<(&'static str, Block, ExpectedHeaderError)> {
        let mut bad_magic = header(b'0', 0);
        bad_magic[IDENTITY_RANGE.start] = b'g';
        let mut bad_version = header(b'0', 0);
        bad_version[IDENTITY_RANGE.end - 2..IDENTITY_RANGE.end].copy_from_slice(b"  ");
        let mut bad_checksum = header(b'0', 0);
        bad_checksum[0] = b'X';
        let mut bad_octal_size = header(b'0', 0);
        bad_octal_size[SIZE_RANGE].copy_from_slice(b"00000000008\0");
        set_checksum(&mut bad_octal_size);
        let mut bad_base256_size = header(b'0', 0);
        bad_base256_size[SIZE_RANGE.start] = 0x80;
        set_checksum(&mut bad_base256_size);

        vec![
            ("magic", bad_magic, ExpectedHeaderError::InvalidIdentity),
            ("version", bad_version, ExpectedHeaderError::InvalidIdentity),
            (
                "checksum",
                bad_checksum,
                ExpectedHeaderError::InvalidChecksum,
            ),
            (
                "octal size",
                bad_octal_size,
                ExpectedHeaderError::InvalidSize,
            ),
            (
                "base256 size",
                bad_base256_size,
                ExpectedHeaderError::InvalidSize,
            ),
            (
                "POSIX typeflag",
                header(b'X', 0),
                ExpectedHeaderError::UnsupportedTypeflag(b'X'),
            ),
            (
                "GNU typeflag",
                header(b'L', 0),
                ExpectedHeaderError::UnsupportedTypeflag(b'L'),
            ),
        ]
    }

    #[test]
    fn frames_bare_member_across_fragmented_reads() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'0', 513));
        append_payload(&mut bytes, &[b'a'; BLOCK_SIZE]);
        append_payload(&mut bytes, b"b");
        append_terminator(&mut bytes);

        let frames = collect(bytes, 7);
        assert_eq!(frames.len(), 3);
        let header = header_frame(&frames, 0);
        assert_eq!(header.kind, MemberKind::Regular);
        assert_eq!(header.declared_size, 513);
        assert_eq!(header.effective_size, 513);
        assert_eq!(header.payload_size, 513);
        assert!(header.global_pax_records.is_empty());
        assert!(header.local_pax_records.is_empty());
        let first = data_frame(&frames, 1);
        let last = data_frame(&frames, 2);
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
        append_posix(&mut bytes, b'x', &payload);
        append_block(&mut bytes, &header(b'0', 1));
        append_payload(&mut bytes, &[b'a'; BLOCK_SIZE]);
        append_payload(&mut bytes, b"b");
        append_terminator(&mut bytes);

        let frames = collect(bytes, 19);
        assert_eq!(frames.len(), 6);
        let Frame::Pax(pax) = frames[0].as_ref().unwrap() else {
            panic!("expected pax header");
        };
        assert_eq!(pax.kind, PaxKind::Local);
        assert_eq!(pax.payload_size, payload.len() as u64);
        let first_pax_data = data_frame(&frames, 1);
        assert_eq!(first_pax_data.owner, DataOwner::Pax(PaxKind::Local));
        assert!(first_pax_data.completed_pax_records.is_none());
        let final_pax_data = data_frame(&frames, 2);
        assert_eq!(final_pax_data.owner, DataOwner::Pax(PaxKind::Local));
        assert_eq!(
            final_pax_data
                .completed_pax_records
                .as_ref()
                .and_then(|records| records.last()),
            Some(&PaxRecord::Size(PaxValue::Value(513)))
        );
        let header = header_frame(&frames, 3);
        assert_eq!(header.declared_size, 1);
        assert_eq!(header.effective_size, 513);
        assert_eq!(header.payload_size, 513);
        assert_eq!(header.local_pax_records.len(), 2);
        assert_eq!(
            header.local_pax_records[1],
            PaxRecord::Size(PaxValue::Value(513))
        );
        let last = data_frame(&frames, 5);
        assert_eq!(last.len, 1);
    }

    #[test]
    fn applies_global_pax_records_overrides_and_rejects_size_deletions() {
        let mut initial_global = record("comment", "old");
        initial_global.extend_from_slice(&record("size", "2"));
        let replacement_global = record("comment", "new");
        let mut local = record("comment", "local");
        local.extend_from_slice(&record("size", "3"));
        let mut deletion = record("comment", "");
        deletion.extend_from_slice(&record("size", ""));

        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'g', &initial_global);
        append_posix(&mut bytes, b'g', &replacement_global);
        append_block(&mut bytes, &header(b'0', 1));
        append_payload(&mut bytes, b"ab");
        append_posix(&mut bytes, b'x', &local);
        append_block(&mut bytes, &header(b'0', 1));
        append_payload(&mut bytes, b"abc");
        append_posix(&mut bytes, b'g', &deletion);
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
            .filter_map(|frame| match frame {
                Ok(Frame::Data(DataFrame {
                    owner: DataOwner::Pax(PaxKind::Global),
                    completed_pax_records: Some(records),
                    ..
                })) => Some(records),
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
            .filter_map(|frame| match frame {
                Ok(Frame::Header(header)) => Some(header),
                _ => None,
            })
            .collect();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].effective_size, 2);
        assert_eq!(
            headers[0].global_pax_records,
            [
                PaxRecord::Size(PaxValue::Value(2)),
                PaxRecord::Comment(PaxValue::Value("new".to_owned())),
            ]
        );
        assert_eq!(headers[1].effective_size, 3);
        assert_eq!(headers[1].local_pax_records, local_records("local", 3));
        assert!(matches!(
            last_error_inner(&frames),
            FrameErrorInner::DeletedPaxMetadata { keyword: "size" }
        ));
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
        append_posix(&mut bytes, b'x', &local);
        append_block(&mut bytes, &header(b'0', 1));
        append_payload(&mut bytes, b"ab");
        append_terminator(&mut bytes);

        let frames = collect(bytes, BLOCK_SIZE);
        let header = header_frame(&frames, 2);
        assert_eq!(header.effective_size, 2);
        assert_eq!(
            header.local_pax_records[0],
            PaxRecord::Size(PaxValue::Deleted)
        );
    }

    #[test]
    fn rejects_local_size_deletion_for_payload_free_members() {
        let global = record("size", "7");
        let local = record("size", "");
        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'g', &global);
        append_posix(&mut bytes, b'x', &local);
        append_block(&mut bytes, &header(b'5', 3));
        append_terminator(&mut bytes);

        assert!(matches!(
            last_error_inner(&collect(bytes, BLOCK_SIZE)),
            FrameErrorInner::DeletedPaxMetadata { keyword: "size" }
        ));
    }

    #[test]
    fn rejects_deleted_size_when_member_payload_cannot_be_framed() {
        let records = record("size", "");
        for typeflag in [b'x', b'g'] {
            let mut bytes = Vec::new();
            append_posix(&mut bytes, typeflag, &records);
            append_block(&mut bytes, &header(b'0', 0));

            assert!(
                matches!(
                    last_error_inner(&collect(bytes, BLOCK_SIZE)),
                    FrameErrorInner::DeletedPaxMetadata { keyword: "size" }
                ),
                "{typeflag:?}"
            );
        }
    }

    #[test]
    fn allows_local_size_to_restore_an_active_global_deletion() {
        let global = record("size", "");
        let local = record("size", "2");
        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'g', &global);
        append_posix(&mut bytes, b'x', &local);
        append_block(&mut bytes, &header(b'0', 1));
        append_payload(&mut bytes, b"ab");
        append_terminator(&mut bytes);

        let frames = collect(bytes, BLOCK_SIZE);
        let header = header_frame(&frames, 4);
        assert_eq!(header.effective_size, 2);
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
        append_payload(&mut bytes, b"abc");
        append_terminator(&mut bytes);

        let frames = collect(bytes, BLOCK_SIZE);
        let header = header_frame(&frames, 0);
        assert_eq!(header.kind, MemberKind::HardLink);
        assert_eq!(header.payload_size, 3);
        let data = data_frame(&frames, 1);
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
        append_posix(&mut bytes, b'x', &payload);
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
        append_payload(&mut bytes, &[b'n'; BLOCK_SIZE]);
        append_payload(&mut bytes, b"\0");
        append_gnu(&mut bytes, b'K', b"link\0");
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
        let final_name = data_frame(&frames, 2);
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
        let header = header_frame(&frames, 5);
        assert_eq!(header.kind, MemberKind::SymbolicLink);
        assert!(header.global_pax_records.is_empty());
        assert!(header.local_pax_records.is_empty());
    }

    #[test]
    fn rejects_header_format_and_type_errors() {
        for (case, block, expected) in invalid_header_cases() {
            let frames = collect(block.to_vec(), BLOCK_SIZE);
            let error = last_error_inner(&frames);
            assert!(expected.matches(error), "{case}: {error:?}");
        }
    }

    #[test]
    fn direct_conversion_errors_preserve_later_header_positions() {
        let position = BLOCK_SIZE as u64;

        for (case, block, expected) in invalid_header_cases() {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &header(b'0', 0));
            append_block(&mut bytes, &block);
            let frames = collect(bytes, BLOCK_SIZE);
            let error = last_error(&frames);
            assert_eq!(error.position, position, "{case}");
            assert!(expected.matches(&error.inner), "{case}: {error:?}");
        }
    }

    #[test]
    fn rejects_invalid_pax_sequences() {
        assert!(matches!(
            last_error_inner(&collect(header(b'x', 0).to_vec(), BLOCK_SIZE)),
            FrameErrorInner::InvalidPaxRecords { .. }
        ));

        let valid = record("path", "name");
        let mut consecutive = Vec::new();
        append_posix(&mut consecutive, b'x', &valid);
        append_block(&mut consecutive, &header(b'x', valid.len() as u64));
        assert!(matches!(
            last_error_inner(&collect(consecutive, BLOCK_SIZE)),
            FrameErrorInner::UnexpectedOrder { .. }
        ));

        let mut missing_member = Vec::new();
        append_posix(&mut missing_member, b'x', &valid);
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
        append_posix(&mut bytes, b'x', &invalid);

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
    fn accepts_binary_and_rejects_unknown_pax_charsets() {
        let mut global = record("hdrcharset", "BINARY");
        global.extend_from_slice(&record("path", "global"));
        let local = record("path", "local");
        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'g', &global);
        append_posix(&mut bytes, b'x', &local);
        append_block(&mut bytes, &header(b'0', 0));
        append_terminator(&mut bytes);
        let frames = collect(bytes, BLOCK_SIZE);
        let member_header = header_frame(&frames, 4);
        assert_eq!(
            member_header.global_pax_records,
            [
                PaxRecord::HdrCharset(PaxValue::Value(HdrCharset::Binary)),
                PaxRecord::Path(PaxValue::Value(PaxString::Binary(b"global".to_vec()))),
            ]
        );
        assert_eq!(
            member_header.local_pax_records,
            [PaxRecord::Path(PaxValue::Value(PaxString::Binary(
                b"local".to_vec()
            )))]
        );

        let records = record("hdrcharset", "ISO-IR 8859 1 1998");
        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'x', &records);
        assert!(matches!(
            last_error_inner(&collect(bytes, BLOCK_SIZE)),
            FrameErrorInner::UnsupportedPaxCharset { value } if value == "ISO-IR 8859 1 1998"
        ));
    }

    #[test]
    fn rejects_invalid_gnu_sequences_and_sizes() {
        let mut duplicate = Vec::new();
        append_block(&mut duplicate, &gnu_header(b'L', 0));
        append_block(&mut duplicate, &gnu_header(b'L', 0));
        let mut long_link_for_regular = Vec::new();
        append_block(&mut long_link_for_regular, &gnu_header(b'K', 0));
        append_block(&mut long_link_for_regular, &gnu_header(b'0', 0));
        let mut dangling = Vec::new();
        append_block(&mut dangling, &gnu_header(b'L', 0));
        append_terminator(&mut dangling);
        for (case, bytes) in [
            ("duplicate", duplicate),
            ("long-link-for-regular", long_link_for_regular),
            ("dangling", dangling),
        ] {
            assert!(
                matches!(
                    last_error_inner(&collect(bytes, BLOCK_SIZE)),
                    FrameErrorInner::UnexpectedOrder { .. }
                ),
                "{case}"
            );
        }

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
                expected: ArchiveFormat::Pax,
                found: ArchiveFormat::Gnu,
            }
        ));

        // A family mismatch applies only to a successfully decoded header.
        let mut malformed_gnu = gnu_header(b'0', 0);
        malformed_gnu[0] = b'X';
        let mut posix_then_malformed_gnu = Vec::new();
        append_block(&mut posix_then_malformed_gnu, &header(b'0', 0));
        append_block(&mut posix_then_malformed_gnu, &malformed_gnu);
        assert!(matches!(
            last_error_inner(&collect(posix_then_malformed_gnu, BLOCK_SIZE)),
            FrameErrorInner::InvalidChecksum { .. }
        ));

        let mut gnu_then_posix = Vec::new();
        append_block(&mut gnu_then_posix, &gnu_header(b'0', 0));
        append_block(&mut gnu_then_posix, &header(b'0', 0));
        assert!(matches!(
            last_error_inner(&collect(gnu_then_posix, BLOCK_SIZE)),
            FrameErrorInner::FormatMismatch {
                expected: ArchiveFormat::Gnu,
                found: ArchiveFormat::Pax,
            }
        ));

        for typeflag in [b'x', b'g'] {
            assert!(
                matches!(
                    last_error_inner(&collect(gnu_header(typeflag, 0).to_vec(), BLOCK_SIZE)),
                    FrameErrorInner::UnsupportedTypeflag { typeflag: found } if *found == typeflag
                ),
                "{typeflag:?}"
            );
        }

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
        append_payload(&mut pax_payload_truncated, b"11 path=x\n");
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
}
