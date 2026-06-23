//! Lossless, block-oriented tar streaming.
//!
//! This API emits one frame for each accepted non-terminator physical
//! tar block and preserves each source block verbatim.
//!
//! The following Mermaid diagram described the state machine:
//!
//! ```mermaid
//! ---
//! config:
//!   layout: elk
//! ---
//!
//! stateDiagram-v2
//!   state "AwaitingHeader (unclassified)" as Unclassified
//!   state SelectFormat <<choice>>
//!
//!   [*] --> Unclassified
//!   Unclassified --> AwaitingSecondZero: first zero block
//!   Unclassified --> SelectFormat: first nonzero header
//!   SelectFormat --> PosixHeader: ustar identity
//!   SelectFormat --> GnuHeader: GNU identity
//!   SelectFormat --> Failed: unsupported identity
//!
//!   state "POSIX-pax selected" as Pax {
//!     direction TB
//!     state "AwaitingHeader" as PosixBoundary
//!     state PosixHeader <<choice>>
//!     state "ReadingMember" as PosixMemberData
//!
//!     PosixBoundary --> PosixHeader: next header
//!     PosixHeader --> ReadingPax: x or g
//!     PosixHeader --> PosixMemberData: member data
//!     PosixHeader --> PosixBoundary: empty member
//!     ReadingPax --> AwaitingUstarHeader: local x payload complete
//!     ReadingPax --> PosixBoundary: global g payload complete
//!     AwaitingUstarHeader --> PosixMemberData: member data
//!     AwaitingUstarHeader --> PosixBoundary: empty member
//!     PosixMemberData --> PosixBoundary: payload complete
//!   }
//!
//!   state "GNU selected" as Gnu {
//!     direction TB
//!     state "AwaitingHeader" as GnuBoundary
//!     state GnuHeader <<choice>>
//!     state "ReadingMember" as GnuMemberData
//!
//!     GnuBoundary --> GnuHeader: next header
//!     GnuHeader --> ReadingGnu: L or K data
//!     GnuHeader --> AwaitingGnuMember: empty L or K
//!     GnuHeader --> GnuMemberData: member data
//!     GnuHeader --> GnuBoundary: empty member
//!     ReadingGnu --> AwaitingGnuMember: metadata payload complete
//!     AwaitingGnuMember --> ReadingGnu: another L or K data
//!     AwaitingGnuMember --> AwaitingGnuMember: another empty L or K
//!     AwaitingGnuMember --> GnuMemberData: member data
//!     AwaitingGnuMember --> GnuBoundary: empty member
//!     GnuMemberData --> GnuBoundary: payload complete
//!   }
//!
//! PosixBoundary --> AwaitingSecondZero: first zero block
//! GnuBoundary --> AwaitingSecondZero: first zero block
//! AwaitingSecondZero --> Complete: second zero block
//! AwaitingSecondZero --> Failed: nonzero block or EOF
//! Complete --> [*]
//! Failed --> [*]
//!
//! note right of Failed
//!   Validation, ordering, and family-mismatch
//!   errors also enter Failed; arrows omitted.
//! end note
//! ```

use std::{
    future::poll_fn,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};
use tokio_stream::Stream;

use crate::{
    ArchiveFormat, BLOCK_SIZE, Block, DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE,
    DEFAULT_MAX_GNU_EXTENSION_SIZE, DEFAULT_MAX_PAX_EXTENSION_SIZE, FrameError, FrameErrorInner,
    GnuKind, HdrCharset, PaxError, PaxKeyword, PaxKind, PaxRecord, PaxState, PaxValue, UstarKind,
    header::{
        CHECKSUM_RANGE, GID_RANGE, GNAME_RANGE, GNU_IDENTITY, IDENTITY_RANGE, LINK_NAME_RANGE,
        MODE_RANGE, MTIME_RANGE, NAME_RANGE, PREFIX_RANGE, SIZE_RANGE, TYPEFLAG_OFFSET, UID_RANGE,
        UNAME_RANGE, USTAR_IDENTITY, checksum, parse_number, parse_octal,
    },
    pax::{GlobalPaxRecords, PaxRecords, SharedPaxRecords},
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

/// An ordinary physical member header block in the selected archive family.
///
/// PAX records remain on their physical payload frames. Use
/// [`crate::logical::TarReader`] for assembled member metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderFrame {
    /// The absolute byte position of this block in the source stream.
    pub position: u64,
    /// The lossless header block bytes.
    pub block: Block,
    /// The selected archive family of this member header.
    pub format: ArchiveFormat,
    /// The member type identified by the header.
    pub kind: UstarKind,
    /// The size encoded directly in the ustar or GNU member header field.
    pub declared_size: u64,
    /// The size after applying applicable pax `size` records.
    ///
    /// This is also the number of payload bytes for which data frames will be
    /// emitted. Member kinds that cannot carry payload are rejected when either
    /// their declared or effective size is nonzero.
    pub effective_size: u64,
}

impl HeaderFrame {
    pub(crate) fn copy_header_path_into(&self, path: &mut Vec<u8>) {
        path.clear();
        let name = trim_nul(&self.block[NAME_RANGE]);
        if self.format == ArchiveFormat::Gnu {
            path.extend_from_slice(name);
            return;
        }
        let prefix = trim_nul(&self.block[PREFIX_RANGE]);
        if !prefix.is_empty() {
            path.extend_from_slice(prefix);
            path.push(b'/');
        }
        path.extend_from_slice(name);
    }

    pub(crate) fn copy_link_name_into(&self, link_name: &mut Vec<u8>) {
        link_name.clear();
        link_name.extend_from_slice(trim_nul(&self.block[LINK_NAME_RANGE]));
    }

    pub(crate) fn mode_bytes(&self) -> [u8; 8] {
        self.block[MODE_RANGE]
            .try_into()
            .expect("fixed header range")
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
    completed_pax_records: Option<SharedPaxRecords>,
}

impl DataFrame {
    /// Returns parsed records completed by this final pax payload block.
    ///
    /// This returns `Some` only for the last data block belonging to a local
    /// or global pax header.
    pub fn completed_pax_records(&self) -> Option<&[PaxRecord]> {
        self.completed_pax_records
            .as_deref()
            .map(PaxRecords::as_slice)
    }

    pub(crate) fn into_completed_pax_records(self) -> Option<SharedPaxRecords> {
        self.completed_pax_records
    }
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
    AwaitingUstarHeader { records: SharedPaxRecords },
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

/// Ordinary-member chunk storage retained across cancellation and API changes.
#[derive(Default)]
struct MemberChunk {
    buffer: Vec<u8>,
    start_position: u64,
    physical_len: usize,
    meaningful_len: usize,
    state: Option<MemberChunkState>,
}

#[derive(Clone, Copy)]
enum MemberChunkState {
    Reading {
        member_remaining: u64,
        filled: usize,
    },
    Ready {
        delivered: usize,
    },
}

/// A strict stream of POSIX-pax or GNU frames sourced from an underlying reader.
pub struct TarStream<R> {
    /// Our current stream position.
    pub(super) position: u64,
    /// Our interior source.
    pub(super) inner: R,
    pub(super) block: Block,
    pub(super) block_len: usize,
    pub(super) format: Option<ArchiveFormat>,
    /// The currently effective global pax records, if any.
    pub(super) global_pax_records: Option<GlobalPaxRecords>,
    max_pax_extension_size: u64,
    max_global_pax_extensions_size: u64,
    global_pax_extensions_size: u64,
    max_gnu_extension_size: u64,
    member_chunk: MemberChunk,
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
            global_pax_records: None,
            max_pax_extension_size: DEFAULT_MAX_PAX_EXTENSION_SIZE,
            max_global_pax_extensions_size: DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE,
            global_pax_extensions_size: 0,
            max_gnu_extension_size: DEFAULT_MAX_GNU_EXTENSION_SIZE,
            member_chunk: MemberChunk::default(),
            state: State::AwaitingHeader,
        }
    }

    /// Sets the maximum size accepted for each subsequent pax extension.
    ///
    /// A local or global header that declares a larger payload is rejected
    /// before its payload is consumed. Setting the maximum to zero rejects
    /// every nonempty extension. Setting it to [`u64::MAX`] removes the
    /// per-extension bound; global extensions remain subject to their
    /// cumulative limit.
    pub fn set_max_pax_extension_size(&mut self, max_pax_extension_size: u64) {
        self.max_pax_extension_size = max_pax_extension_size;
    }

    /// Sets the maximum cumulative size accepted for global pax extensions
    /// before one ordinary member.
    ///
    /// The total resets after each ordinary member. A global header that would
    /// increase the pending total beyond this limit is rejected before its
    /// payload is consumed. Setting the maximum to zero rejects every nonempty
    /// global extension. Setting it to [`u64::MAX`] removes the cumulative
    /// bound; each extension remains subject to its individual limit.
    pub fn set_max_global_pax_extensions_size(&mut self, max_global_pax_extensions_size: u64) {
        self.max_global_pax_extensions_size = max_global_pax_extensions_size;
    }

    /// Sets the maximum size accepted for each GNU extension.
    ///
    /// A GNU extension member that declares a larger payload is rejected before
    /// its payload is consumed. Setting the maximum to zero rejects every nonempty
    /// GNU extension member. Setting it to [`u64::MAX`] removes the per-extension bound.
    pub fn set_max_gnu_extension_size(&mut self, max_gnu_extension_size: u64) {
        self.max_gnu_extension_size = max_gnu_extension_size;
    }

    /// Returns the selected archive family after the first header is read.
    pub fn format(&self) -> Option<ArchiveFormat> {
        self.format
    }
}

impl<R: AsyncRead + Unpin> TarStream<R> {
    /// Reads one ordinary-member payload block without constructing a [`Frame`].
    ///
    /// Returns the block's position, lossless bytes, and meaningful length.
    pub(crate) async fn read_member_block(&mut self) -> Result<(u64, Block, usize), FrameError> {
        if self.member_chunk.state.is_some() {
            self.complete_member_chunk().await?;
            return self.take_member_block_from_chunk();
        }
        let remaining = match &self.state {
            State::ReadingMember { remaining } => *remaining,
            _ => {
                self.state = State::Failed;
                return Err(FrameError::unexpected_order(
                    self.position,
                    "ordinary member payload",
                    "parser state without member payload",
                ));
            }
        };
        let (position, block) = match poll_fn(|context| self.poll_read_block(context)).await {
            Ok(Some(block)) => block,
            Ok(None) => {
                let error = self.handle_eof();
                self.state = State::Failed;
                return Err(error);
            }
            Err(error) => {
                self.state = State::Failed;
                return Err(error);
            }
        };
        let meaningful_len = remaining.min(BLOCK_SIZE as u64) as usize;
        self.state = member_payload_state(remaining - meaningful_len as u64);
        Ok((position, block, meaningful_len))
    }

    /// Reads aligned ordinary-member payload blocks directly into `buffer`.
    ///
    /// This internal path preserves exact physical-block completion checks
    /// while avoiding lossless [`Frame`] construction for chunk consumers.
    pub(crate) async fn read_member_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<usize, FrameError> {
        // A cancelled block read retains its partial physical block here. Finish
        // and deliver it before starting a direct chunk so no bytes are lost.
        if self.member_chunk.state.is_none() && self.block_len != 0 {
            let (_, block, meaningful_len) = self.read_member_block().await?;
            buffer.clear();
            buffer.extend_from_slice(&block[..meaningful_len]);
            return Ok(meaningful_len);
        }
        if self.member_chunk.state.is_none() {
            self.start_member_chunk(buffer, target_len)?;
        }
        self.complete_member_chunk().await?;
        self.take_member_chunk(buffer)
    }

    fn start_member_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<(), FrameError> {
        let member_remaining = match &self.state {
            State::ReadingMember { remaining } => *remaining,
            _ => {
                self.state = State::Failed;
                return Err(FrameError::unexpected_order(
                    self.position,
                    "ordinary member payload",
                    "parser state without member payload",
                ));
            }
        };
        if self.block_len != 0 {
            self.state = State::Failed;
            return Err(FrameError::unexpected_order(
                self.position,
                "aligned ordinary member payload",
                "partially buffered physical block",
            ));
        }

        let target_len = u64::try_from(target_len.max(BLOCK_SIZE)).map_err(|_| {
            FrameError::arithmetic_overflow(self.position, "member payload chunk target length")
        })?;
        let physical_len = member_remaining
            .min(target_len)
            .div_ceil(BLOCK_SIZE as u64)
            .checked_mul(BLOCK_SIZE as u64)
            .ok_or_else(|| {
                FrameError::arithmetic_overflow(
                    self.position,
                    "member payload chunk physical length",
                )
            })?;
        let meaningful_len = member_remaining.min(physical_len);
        let physical_len = usize::try_from(physical_len).map_err(|_| {
            FrameError::arithmetic_overflow(self.position, "member payload chunk physical length")
        })?;
        let meaningful_len = usize::try_from(meaningful_len).map_err(|_| {
            FrameError::arithmetic_overflow(self.position, "member payload chunk meaningful length")
        })?;

        // Move the caller's reusable allocation into persistent storage before
        // reading so cancellation cannot discard partial bytes or progress.
        self.member_chunk.buffer.clear();
        std::mem::swap(buffer, &mut self.member_chunk.buffer);
        if self.member_chunk.buffer.len() != physical_len {
            self.member_chunk.buffer.resize(physical_len, 0);
        }
        self.member_chunk.start_position = self.position;
        self.member_chunk.physical_len = physical_len;
        self.member_chunk.meaningful_len = meaningful_len;
        self.member_chunk.state = Some(MemberChunkState::Reading {
            member_remaining,
            filled: 0,
        });
        Ok(())
    }

    async fn complete_member_chunk(&mut self) -> Result<(), FrameError> {
        loop {
            let (member_remaining, filled) = match self.member_chunk.state {
                Some(MemberChunkState::Reading {
                    member_remaining,
                    filled,
                }) => (member_remaining, filled),
                Some(MemberChunkState::Ready { .. }) => return Ok(()),
                None => {
                    self.state = State::Failed;
                    return Err(FrameError::unexpected_order(
                        self.position,
                        "pending member payload chunk",
                        "parser state without a pending chunk",
                    ));
                }
            };
            let start_position = self.member_chunk.start_position;
            let physical_len = self.member_chunk.physical_len;
            let meaningful_len = self.member_chunk.meaningful_len;
            if filled == physical_len {
                self.position =
                    checked_position(start_position, physical_len).inspect_err(|_| {
                        self.state = State::Failed;
                        self.member_chunk.state = None;
                    })?;
                let remaining = member_remaining
                    .checked_sub(meaningful_len as u64)
                    .ok_or_else(|| {
                        self.state = State::Failed;
                        self.member_chunk.state = None;
                        FrameError::arithmetic_overflow(
                            start_position,
                            "remaining member payload length",
                        )
                    })?;
                self.state = member_payload_state(remaining);
                self.member_chunk.state = Some(MemberChunkState::Ready { delivered: 0 });
                return Ok(());
            }

            let read = match poll_fn(|context| {
                let mut read_buffer =
                    ReadBuf::new(&mut self.member_chunk.buffer[filled..physical_len]);
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
                    self.member_chunk.state = None;
                    let error_position = checked_position(start_position, filled)?;
                    self.position = checked_position(start_position, filled - filled % BLOCK_SIZE)?;
                    return Err(FrameError::at(
                        error_position,
                        FrameErrorInner::Io { source },
                    ));
                }
            };
            if read == 0 {
                self.state = State::Failed;
                self.member_chunk.state = None;
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
                    FrameError::arithmetic_overflow(
                        self.position,
                        "completed member payload chunk length",
                    )
                })?;
                return Err(FrameError::truncated_payload(
                    self.position,
                    DataOwner::Member,
                    member_remaining - member_remaining.min(completed_len),
                ));
            }
            if let Some(MemberChunkState::Reading { filled, .. }) = &mut self.member_chunk.state {
                *filled += read;
            }
        }
    }

    fn take_member_chunk(&mut self, buffer: &mut Vec<u8>) -> Result<usize, FrameError> {
        let Some(MemberChunkState::Ready { delivered }) = self.member_chunk.state.take() else {
            self.state = State::Failed;
            return Err(FrameError::unexpected_order(
                self.position,
                "completed member payload chunk",
                "incomplete member payload chunk",
            ));
        };
        let meaningful_len = self.member_chunk.meaningful_len;
        let remaining_len = meaningful_len.checked_sub(delivered).ok_or_else(|| {
            self.state = State::Failed;
            FrameError::arithmetic_overflow(self.position, "undelivered member payload length")
        })?;
        if delivered != 0 {
            self.member_chunk
                .buffer
                .copy_within(delivered..meaningful_len, 0);
        }
        self.member_chunk.buffer.truncate(remaining_len);
        std::mem::swap(buffer, &mut self.member_chunk.buffer);
        Ok(remaining_len)
    }

    fn take_member_block_from_chunk(&mut self) -> Result<(u64, Block, usize), FrameError> {
        let Some(MemberChunkState::Ready { delivered }) = self.member_chunk.state else {
            self.state = State::Failed;
            return Err(FrameError::unexpected_order(
                self.position,
                "completed member payload chunk",
                "incomplete member payload chunk",
            ));
        };
        let start_position = self.member_chunk.start_position;
        let physical_len = self.member_chunk.physical_len;
        let total_meaningful_len = self.member_chunk.meaningful_len;
        let position = checked_position(start_position, delivered).inspect_err(|_| {
            self.state = State::Failed;
            self.member_chunk.state = None;
        })?;
        let mut block = [0; BLOCK_SIZE];
        block.copy_from_slice(&self.member_chunk.buffer[delivered..delivered + BLOCK_SIZE]);
        let meaningful_len = total_meaningful_len
            .checked_sub(delivered)
            .ok_or_else(|| {
                self.state = State::Failed;
                self.member_chunk.state = None;
                FrameError::arithmetic_overflow(self.position, "undelivered member payload length")
            })?
            .min(BLOCK_SIZE);
        let delivered = delivered + BLOCK_SIZE;
        if delivered == physical_len {
            self.member_chunk.state = None;
        } else {
            self.member_chunk.state = Some(MemberChunkState::Ready { delivered });
        }
        Ok((position, block, meaningful_len))
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
            .ok_or_else(|| FrameError::arithmetic_overflow(position, "stream position"))?;
        self.block_len = 0;
        let block = std::mem::replace(&mut self.block, [0; BLOCK_SIZE]);
        Poll::Ready(Ok(Some((position, block))))
    }

    fn handle_eof(&mut self) -> FrameError {
        let inner = match &self.state {
            State::AwaitingHeader | State::AwaitingSecondZero => FrameErrorInner::MissingEndMarker,
            State::ReadingPax {
                kind, remaining, ..
            } => FrameErrorInner::TruncatedPayload {
                owner: DataOwner::Pax(*kind),
                remaining: *remaining,
            },
            State::AwaitingUstarHeader { .. } => FrameErrorInner::UnexpectedEof {
                expected: "ordinary ustar member header after a local pax header",
            },
            State::ReadingGnu {
                kind, remaining, ..
            } => FrameErrorInner::TruncatedPayload {
                owner: DataOwner::Gnu(*kind),
                remaining: *remaining,
            },
            State::AwaitingGnuMember { .. } => FrameErrorInner::UnexpectedEof {
                expected: "ordinary GNU member header after a GNU metadata extension",
            },
            State::ReadingMember { remaining } => FrameErrorInner::TruncatedPayload {
                owner: DataOwner::Member,
                remaining: *remaining,
            },
            State::Complete | State::Failed => FrameErrorInner::UnexpectedEof {
                expected: "no further input",
            },
        };
        FrameError::at(self.position, inner)
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
                    let records = Arc::new(
                        PaxRecords::parse(
                            &payload,
                            self.global_pax_records
                                .as_ref()
                                .map_or(HdrCharset::Utf8, GlobalPaxRecords::hdrcharset),
                        )
                        .map_err(|source| {
                            FrameError::invalid_pax_record(header_position, source)
                        })?,
                    );
                    match kind {
                        PaxKind::Local => {
                            self.state = State::AwaitingUstarHeader {
                                records: records.clone(),
                            };
                        }
                        PaxKind::Global => {
                            records.apply_global(&mut self.global_pax_records);
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
                    return Err(FrameError::unexpected_order(
                        position,
                        "ordinary ustar member header after a local pax header",
                        "end-of-archive marker",
                    ));
                }
                let parsed = self.parse_format_checked_header(position, &block)?;
                if matches!(parsed.typeflag, b'x' | b'g') {
                    return Err(FrameError::unexpected_order(
                        position,
                        "ordinary ustar member header after a local pax header",
                        "another pax extended header",
                    ));
                }
                self.process_ustar_header(position, block, parsed, Some(records))
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
                    return Err(FrameError::unexpected_order(
                        position,
                        "ordinary GNU member header after a GNU metadata extension",
                        "end-of-archive marker",
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
            State::Failed => Ok(None),
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
            _ => self.process_ustar_header(position, block, parsed, None),
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
        if payload_size > self.max_pax_extension_size {
            return Err(FrameError::at(
                position,
                FrameErrorInner::ExtensionTooLarge {
                    format: ArchiveFormat::Pax,
                    size: payload_size,
                    limit: self.max_pax_extension_size,
                },
            ));
        }
        if kind == PaxKind::Global {
            let size = self
                .global_pax_extensions_size
                .checked_add(payload_size)
                .ok_or_else(|| {
                    FrameError::arithmetic_overflow(position, "global pax extension payload total")
                })?;
            if size > self.max_global_pax_extensions_size {
                return Err(FrameError::at(
                    position,
                    FrameErrorInner::GlobalPaxExtensionsTooLarge {
                        size,
                        limit: self.max_global_pax_extensions_size,
                    },
                ));
            }
            self.global_pax_extensions_size = size;
        }
        if payload_size == 0 {
            return Err(FrameError::invalid_pax_record(
                position,
                PaxError::InvalidRecords {
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
        local_pax_records: Option<SharedPaxRecords>,
    ) -> Result<Frame, FrameError> {
        let kind = UstarKind::try_from_framed(position, parsed.typeflag)?;
        validate_posix_member_header_fields(
            position,
            &block,
            local_pax_records.as_deref(),
            self.global_pax_records.as_ref(),
        )?;
        let effective_size = PaxState::effective_size(
            local_pax_records.as_deref(),
            self.global_pax_records.as_ref(),
        )
        .map_or(Ok(parsed.size), |size| match size {
            PaxValue::Value(size) => Ok(*size),
            PaxValue::Deleted => Err(FrameError::deleted_pax_metadata(position, "size")),
        })?;
        validate_posix_member_size(position, kind, parsed.size, effective_size)?;
        self.global_pax_extensions_size = 0;
        self.state = member_payload_state(effective_size);
        Ok(Frame::Header(HeaderFrame {
            position,
            block,
            format: ArchiveFormat::Pax,
            kind,
            declared_size: parsed.size,
            effective_size,
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
                return Err(FrameError::unexpected_order(
                    position,
                    "ordinary GNU member header or the other GNU metadata extension",
                    "duplicate GNU metadata extension",
                ));
            }
            if parsed.size > self.max_gnu_extension_size {
                return Err(FrameError::at(
                    position,
                    FrameErrorInner::ExtensionTooLarge {
                        format: ArchiveFormat::Gnu,
                        size: parsed.size,
                        limit: self.max_gnu_extension_size,
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

        let kind = UstarKind::try_from_framed(position, parsed.typeflag)?;
        if pending.long_link && !matches!(kind, UstarKind::HardLink | UstarKind::SymbolicLink) {
            return Err(FrameError::unexpected_order(
                position,
                "hard-link or symbolic-link member after GNU long-link extension",
                "non-link ordinary member",
            ));
        }
        validate_gnu_member_size(position, kind, parsed.size)?;
        self.state = member_payload_state(parsed.size);
        Ok(Frame::Header(HeaderFrame {
            position,
            block,
            format: ArchiveFormat::Gnu,
            kind,
            declared_size: parsed.size,
            effective_size: parsed.size,
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

fn checked_position(position: u64, len: usize) -> Result<u64, FrameError> {
    let len = u64::try_from(len)
        .map_err(|_| FrameError::arithmetic_overflow(position, "stream position"))?;
    position
        .checked_add(len)
        .ok_or_else(|| FrameError::arithmetic_overflow(position, "stream position"))
}

impl TryFromFramed<&Block> for ParsedHeader {
    fn try_from_framed(position: u64, block: &Block) -> Result<Self, FrameError> {
        let format = match &block[IDENTITY_RANGE] {
            identity if identity == USTAR_IDENTITY => ArchiveFormat::Pax,
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

impl TryFromFramed<u8> for UstarKind {
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

fn validate_posix_member_size(
    position: u64,
    kind: UstarKind,
    declared_size: u64,
    effective_size: u64,
) -> Result<(), FrameError> {
    match kind {
        // PAX permits a nonzero physical hardlink size and allows pax `size`
        // records to override it, so the effective size controls framing.
        // This is a broadening of what ustar allows; ustar requires
        // hardlink members to have `size=0`.
        UstarKind::Regular | UstarKind::HardLink | UstarKind::Contiguous => Ok(()),
        UstarKind::SymbolicLink
        | UstarKind::CharacterDevice
        | UstarKind::BlockDevice
        | UstarKind::Directory
        | UstarKind::Fifo => {
            // NOTE: Observe that we're strict about directory entries having
            // `size=0`, even though ustar/pax says that they may have a nonzero
            // size as an allocation hint (which, in turn, does not affect framing).
            // We do this to avoid a common differential where some parsers incorrectly
            // honor the directory entry's size during framing.
            // TODO: Make this configurable? Doing so seems very risky.
            validate_payload_free_size(position, kind, declared_size)?;
            validate_payload_free_size(position, kind, effective_size)
        }
    }
}

fn validate_posix_member_header_fields(
    position: u64,
    block: &Block,
    local_records: Option<&PaxRecords>,
    global_records: Option<&GlobalPaxRecords>,
) -> Result<(), FrameError> {
    let mode: [u8; 8] = block[MODE_RANGE].try_into().expect("fixed header range");
    match parse_octal(&mode) {
        Some(0..=0o7777) => {}
        _ => {
            return Err(FrameError::at(
                position,
                FrameErrorInner::InvalidMode { found: mode },
            ));
        }
    }

    for (field, range, keyword) in [
        ("uid", UID_RANGE, PaxKeyword::Uid),
        ("gid", GID_RANGE, PaxKeyword::Gid),
        ("mtime", MTIME_RANGE, PaxKeyword::Mtime),
    ] {
        if PaxState::effective_record_from(local_records, global_records, &keyword).is_some() {
            continue;
        }
        let bytes = &block[range];
        if parse_octal(bytes).is_none() {
            return Err(FrameError::at(
                position,
                FrameErrorInner::InvalidUstarNumericField {
                    field,
                    found: bytes.to_vec(),
                },
            ));
        }
    }

    for (field, range, keyword) in [
        ("uname", UNAME_RANGE, PaxKeyword::Uname),
        ("gname", GNAME_RANGE, PaxKeyword::Gname),
    ] {
        if PaxState::effective_record_from(local_records, global_records, &keyword).is_none()
            && !block[range].contains(&0)
        {
            return Err(FrameError::at(
                position,
                FrameErrorInner::UnterminatedUstarStringField { field },
            ));
        }
    }

    // POSIX deliberately leaves the representation of device numbers unspecified.
    // We do not consume those fields, so devmajor and devminor remain opaque.
    Ok(())
}

fn validate_gnu_member_size(position: u64, kind: UstarKind, size: u64) -> Result<(), FrameError> {
    match kind {
        UstarKind::Regular | UstarKind::Contiguous => Ok(()),
        UstarKind::HardLink
        | UstarKind::SymbolicLink
        | UstarKind::CharacterDevice
        | UstarKind::BlockDevice
        | UstarKind::Directory
        | UstarKind::Fifo => validate_payload_free_size(position, kind, size),
    }
}

fn validate_payload_free_size(position: u64, kind: UstarKind, size: u64) -> Result<(), FrameError> {
    if size == 0 {
        Ok(())
    } else {
        Err(FrameError::at(
            position,
            FrameErrorInner::InvalidMemberSize { kind, size },
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        pin::Pin,
        rc::Rc,
        task::{Context, Poll},
    };

    use tokio::io::ReadBuf;
    use tokio_stream::{Stream, StreamExt};

    use super::*;
    use crate::{
        ArchiveFormat, FrameError, FrameErrorInner, HdrCharset, PaxString, PaxValue,
        header::{DEVMAJOR_RANGE, DEVMINOR_RANGE},
        test_support::{
            ChunkedReader, append_block, append_gnu, append_payload, append_posix,
            append_terminator, gnu_base256_header, gnu_header, header, ready, record, set_checksum,
        },
    };

    fn collect(bytes: Vec<u8>, max_chunk: usize) -> Vec<Result<Frame, FrameError>> {
        ready(TarStream::new(ChunkedReader::new(bytes, max_chunk)).collect())
    }

    fn collect_with_max_pax_extension_size(
        bytes: Vec<u8>,
        max_chunk: usize,
        max_pax_extension_size: u64,
    ) -> Vec<Result<Frame, FrameError>> {
        let mut stream = TarStream::new(ChunkedReader::new(bytes, max_chunk));
        stream.set_max_pax_extension_size(max_pax_extension_size);
        ready(stream.collect())
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

    struct CountingReader {
        bytes: Vec<u8>,
        position: usize,
        consumed: Rc<Cell<usize>>,
    }

    impl AsyncRead for CountingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let len = buffer
                .remaining()
                .min(self.bytes.len().saturating_sub(self.position));
            let end = self.position + len;
            buffer.put_slice(&self.bytes[self.position..end]);
            self.position = end;
            self.consumed.set(self.consumed.get() + len);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone, Copy)]
    enum ExpectedHeaderError {
        InvalidIdentity,
        InvalidChecksum,
        InvalidSize,
        InvalidMode,
        InvalidUstarNumericField(&'static str),
        UnterminatedUstarStringField(&'static str),
        UnsupportedTypeflag(u8),
    }

    impl ExpectedHeaderError {
        fn matches(self, error: &FrameErrorInner) -> bool {
            match (self, error) {
                (Self::InvalidIdentity, FrameErrorInner::InvalidIdentity { .. })
                | (Self::InvalidChecksum, FrameErrorInner::InvalidChecksum { .. })
                | (Self::InvalidSize, FrameErrorInner::InvalidSize { .. })
                | (Self::InvalidMode, FrameErrorInner::InvalidMode { .. }) => true,
                (
                    Self::InvalidUstarNumericField(field),
                    FrameErrorInner::InvalidUstarNumericField { field: found, .. },
                )
                | (
                    Self::UnterminatedUstarStringField(field),
                    FrameErrorInner::UnterminatedUstarStringField { field: found },
                ) => field == *found,
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
        let mut bad_octal_mode = header(b'0', 0);
        bad_octal_mode[MODE_RANGE].copy_from_slice(b"0000080\0");
        set_checksum(&mut bad_octal_mode);
        let mut oversized_mode = header(b'0', 0);
        oversized_mode[MODE_RANGE].copy_from_slice(b"0010000\0");
        set_checksum(&mut oversized_mode);
        let mut bad_uid = header(b'0', 0);
        bad_uid[UID_RANGE].copy_from_slice(b"invalid\0");
        set_checksum(&mut bad_uid);
        let mut bad_gid = header(b'0', 0);
        bad_gid[GID_RANGE].fill(0);
        set_checksum(&mut bad_gid);
        let mut bad_mtime = header(b'0', 0);
        bad_mtime[MTIME_RANGE].copy_from_slice(b"00000000008\0");
        set_checksum(&mut bad_mtime);
        let mut unterminated_uname = header(b'0', 0);
        unterminated_uname[UNAME_RANGE].fill(b'u');
        set_checksum(&mut unterminated_uname);
        let mut unterminated_gname = header(b'0', 0);
        unterminated_gname[GNAME_RANGE].fill(b'g');
        set_checksum(&mut unterminated_gname);

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
                "octal mode",
                bad_octal_mode,
                ExpectedHeaderError::InvalidMode,
            ),
            (
                "oversized mode",
                oversized_mode,
                ExpectedHeaderError::InvalidMode,
            ),
            (
                "uid",
                bad_uid,
                ExpectedHeaderError::InvalidUstarNumericField("uid"),
            ),
            (
                "gid",
                bad_gid,
                ExpectedHeaderError::InvalidUstarNumericField("gid"),
            ),
            (
                "mtime",
                bad_mtime,
                ExpectedHeaderError::InvalidUstarNumericField("mtime"),
            ),
            (
                "uname",
                unterminated_uname,
                ExpectedHeaderError::UnterminatedUstarStringField("uname"),
            ),
            (
                "gname",
                unterminated_gname,
                ExpectedHeaderError::UnterminatedUstarStringField("gname"),
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
        assert_eq!(header.kind, UstarKind::Regular);
        assert_eq!(header.declared_size, 513);
        assert_eq!(header.effective_size, 513);
        let first = data_frame(&frames, 1);
        let last = data_frame(&frames, 2);
        assert_eq!(first.len, BLOCK_SIZE);
        assert_eq!(last.len, 1);
        assert_eq!(last.owner, DataOwner::Member);
        assert!(first.completed_pax_records().is_none());
        assert!(last.completed_pax_records().is_none());
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
        assert!(first_pax_data.completed_pax_records().is_none());
        let final_pax_data = data_frame(&frames, 2);
        assert_eq!(final_pax_data.owner, DataOwner::Pax(PaxKind::Local));
        assert_eq!(
            final_pax_data
                .completed_pax_records()
                .and_then(|records| records.last()),
            Some(&PaxRecord::Size(PaxValue::Value(513)))
        );
        let header = header_frame(&frames, 3);
        assert_eq!(header.declared_size, 1);
        assert_eq!(header.effective_size, 513);
        let last = data_frame(&frames, 5);
        assert_eq!(last.len, 1);
    }

    #[test]
    fn rejects_oversized_pax_extensions_before_consuming_payload() {
        let mut payload = record("comment", "metadata");
        payload.extend_from_slice(&record("mtime", "1"));
        let declared_size = u64::try_from(payload.len()).expect("payload size should fit u64");
        for (case, typeflag) in [("local", b'x'), ("global", b'g')] {
            let mut bytes = Vec::new();
            append_posix(&mut bytes, typeflag, &payload);
            let frames = collect_with_max_pax_extension_size(bytes, BLOCK_SIZE, declared_size - 1);
            assert_eq!(frames.len(), 1, "{case}");
            assert!(matches!(
                last_error(&frames),
                FrameError {
                    position: 0,
                    inner: FrameErrorInner::ExtensionTooLarge {
                        format: ArchiveFormat::Pax,
                        size,
                        limit,
                    },
                } if *size == declared_size && *limit == declared_size - 1
            ));
        }

        let frames = collect(
            header(b'x', DEFAULT_MAX_PAX_EXTENSION_SIZE + 1).to_vec(),
            BLOCK_SIZE,
        );
        assert_eq!(frames.len(), 1);
        assert!(matches!(
            last_error(&frames),
            FrameError {
                position: 0,
                inner: FrameErrorInner::ExtensionTooLarge {
                    format: ArchiveFormat::Pax,
                    size,
                    limit: DEFAULT_MAX_PAX_EXTENSION_SIZE,
                },
            } if *size == DEFAULT_MAX_PAX_EXTENSION_SIZE + 1
        ));
    }

    #[test]
    fn oversized_pax_extension_does_not_read_its_payload_block() {
        let mut bytes = header(b'x', 1).to_vec();
        bytes.resize(BLOCK_SIZE * 2, 0);
        let consumed = Rc::new(Cell::new(0));
        let reader = CountingReader {
            bytes,
            position: 0,
            consumed: Rc::clone(&consumed),
        };
        let mut stream = TarStream::new(reader);
        stream.set_max_pax_extension_size(0);

        assert!(matches!(
            ready(stream.next()),
            Some(Err(FrameError {
                position: 0,
                inner: FrameErrorInner::ExtensionTooLarge {
                    format: ArchiveFormat::Pax,
                    size: 1,
                    limit: 0,
                },
            }))
        ));
        assert_eq!(consumed.get(), BLOCK_SIZE);
    }

    #[test]
    fn accepts_pax_extensions_at_the_configured_limit() {
        let mut payload = record("comment", "metadata");
        payload.extend_from_slice(&record("ACME.attribute", "value"));
        for (case, typeflag) in [("local", b'x'), ("global", b'g')] {
            let mut bytes = Vec::new();
            append_posix(&mut bytes, typeflag, &payload);
            if typeflag == b'x' {
                append_block(&mut bytes, &header(b'0', 0));
            }
            append_terminator(&mut bytes);

            let frames = collect_with_max_pax_extension_size(
                bytes,
                7,
                payload
                    .len()
                    .try_into()
                    .expect("payload size should fit u64"),
            );
            assert!(frames.iter().all(Result::is_ok), "{case}");
        }
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
        let completed_global_payloads: Vec<&[PaxRecord]> = frames
            .iter()
            .filter_map(|frame| match frame {
                Ok(Frame::Data(frame)) if frame.owner == DataOwner::Pax(PaxKind::Global) => {
                    frame.completed_pax_records()
                }
                _ => None,
            })
            .collect();
        assert_eq!(completed_global_payloads.len(), 3);
        assert_eq!(
            completed_global_payloads[2],
            [
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
        assert_eq!(headers[1].effective_size, 3);
        assert!(frames.iter().any(|frame| {
            matches!(
                frame,
                Ok(Frame::Data(frame))
                    if frame.owner == DataOwner::Pax(PaxKind::Local)
                        && frame.completed_pax_records() == Some(local_records("local", 3).as_slice())
            )
        }));
        assert!(matches!(
            last_error_inner(&frames),
            FrameErrorInner::DeletedPaxMetadata { keyword: "size" }
        ));
    }

    fn local_records(comment: &str, size: u64) -> Vec<PaxRecord> {
        vec![
            PaxRecord::Comment(PaxValue::Value(comment.into())),
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
            data_frame(&frames, 1).completed_pax_records(),
            Some(
                [
                    PaxRecord::Size(PaxValue::Deleted),
                    PaxRecord::Size(PaxValue::Value(2)),
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn pax_records_override_malformed_ordinary_header_fields() {
        let mut malformed = header(b'0', 0);
        malformed[UID_RANGE].fill(b'u');
        malformed[GID_RANGE].fill(b'g');
        malformed[MTIME_RANGE].fill(b'm');
        malformed[UNAME_RANGE].fill(b'u');
        malformed[GNAME_RANGE].fill(b'g');
        set_checksum(&mut malformed);

        let local_values = [
            record("uid", "1"),
            record("gid", "2"),
            record("mtime", "3"),
            record("uname", "user"),
            record("gname", "group"),
        ]
        .concat();
        let global_deletions = [
            record("uid", ""),
            record("gid", ""),
            record("mtime", ""),
            record("uname", ""),
            record("gname", ""),
        ]
        .concat();

        for (case, typeflag, records) in [
            ("local values", b'x', local_values),
            ("global deletions", b'g', global_deletions),
        ] {
            let mut bytes = Vec::new();
            append_posix(&mut bytes, typeflag, &records);
            append_block(&mut bytes, &malformed);
            append_terminator(&mut bytes);

            let frames = collect(bytes, BLOCK_SIZE);
            assert!(frames.iter().all(Result::is_ok), "{case}: {frames:?}");
        }
    }

    #[test]
    fn accepts_all_nul_unused_device_fields() {
        let block = header(b'0', 0);
        assert_eq!(parse_octal(&block[DEVMAJOR_RANGE]), None);
        assert_eq!(parse_octal(&block[DEVMINOR_RANGE]), None);

        let mut bytes = Vec::new();
        append_block(&mut bytes, &block);
        append_terminator(&mut bytes);
        assert!(collect(bytes, BLOCK_SIZE).iter().all(Result::is_ok));
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
            data_frame(&frames, 1).completed_pax_records(),
            Some([PaxRecord::Size(PaxValue::Deleted)].as_slice())
        );
        assert_eq!(
            data_frame(&frames, 3).completed_pax_records(),
            Some([PaxRecord::Size(PaxValue::Value(2))].as_slice())
        );
    }

    #[test]
    fn frames_pax_hard_link_bodies_from_header_or_size_override() {
        for (case, declared_size, override_size, header_index, data_index) in [
            ("physical size", 3, None, 0, 1),
            ("pax size", 0, Some("3"), 2, 3),
            ("pax size overrides physical size", 1, Some("3"), 2, 3),
        ] {
            let mut bytes = Vec::new();
            if let Some(override_size) = override_size {
                append_posix(&mut bytes, b'x', &record("size", override_size));
            }
            append_block(&mut bytes, &header(b'1', declared_size));
            append_payload(&mut bytes, b"abc");
            append_terminator(&mut bytes);

            let frames = collect(bytes, BLOCK_SIZE);
            let header = header_frame(&frames, header_index);
            assert_eq!(header.format, ArchiveFormat::Pax, "{case}");
            assert_eq!(header.kind, UstarKind::HardLink, "{case}");
            assert_eq!(header.declared_size, declared_size, "{case}");
            assert_eq!(header.effective_size, 3, "{case}");
            assert_eq!(data_frame(&frames, data_index).len, 3, "{case}");
        }
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
        assert!(final_name.completed_pax_records().is_none());
        assert!(matches!(
            frames[3].as_ref().unwrap(),
            Frame::Gnu(GnuFrame {
                kind: GnuKind::LongLink,
                ..
            })
        ));
        let header = header_frame(&frames, 5);
        assert_eq!(header.kind, UstarKind::SymbolicLink);
    }

    #[test]
    fn rejects_header_format_type_and_field_errors() {
        for (case, block, expected) in invalid_header_cases() {
            let frames = collect(block.to_vec(), BLOCK_SIZE);
            let error = last_error_inner(&frames);
            assert!(expected.matches(error), "{case}: {error:?}");
        }
    }

    #[test]
    fn rejects_nonzero_physical_sizes_for_payload_free_members() {
        for (format, block, kind) in [
            (ArchiveFormat::Pax, header(b'2', 1), UstarKind::SymbolicLink),
            (ArchiveFormat::Gnu, gnu_header(b'1', 1), UstarKind::HardLink),
            (
                ArchiveFormat::Gnu,
                gnu_header(b'2', 1),
                UstarKind::SymbolicLink,
            ),
            (
                ArchiveFormat::Pax,
                header(b'3', 1),
                UstarKind::CharacterDevice,
            ),
            (
                ArchiveFormat::Gnu,
                gnu_header(b'3', 1),
                UstarKind::CharacterDevice,
            ),
            (ArchiveFormat::Pax, header(b'4', 1), UstarKind::BlockDevice),
            (
                ArchiveFormat::Gnu,
                gnu_header(b'4', 1),
                UstarKind::BlockDevice,
            ),
            (ArchiveFormat::Pax, header(b'5', 1), UstarKind::Directory),
            (
                ArchiveFormat::Gnu,
                gnu_header(b'5', 1),
                UstarKind::Directory,
            ),
            (ArchiveFormat::Pax, header(b'6', 1), UstarKind::Fifo),
            (ArchiveFormat::Gnu, gnu_header(b'6', 1), UstarKind::Fifo),
        ] {
            let frames = collect(block.to_vec(), BLOCK_SIZE);
            assert!(
                matches!(
                    last_error_inner(&frames),
                    FrameErrorInner::InvalidMemberSize {
                        kind: found,
                        size: 1,
                    } if *found == kind
                ),
                "{format:?} {kind:?}"
            );
        }
    }

    #[test]
    fn rejects_nonzero_declared_or_effective_pax_sizes_for_payload_free_members() {
        for (case, declared_size, override_size) in [("effective", 0, "1"), ("declared", 1, "0")] {
            for (typeflag, kind) in [
                (b'2', UstarKind::SymbolicLink),
                (b'3', UstarKind::CharacterDevice),
                (b'4', UstarKind::BlockDevice),
                (b'5', UstarKind::Directory),
                (b'6', UstarKind::Fifo),
            ] {
                let mut bytes = Vec::new();
                append_posix(&mut bytes, b'x', &record("size", override_size));
                append_block(&mut bytes, &header(typeflag, declared_size));

                assert!(
                    matches!(
                        last_error_inner(&collect(bytes, BLOCK_SIZE)),
                        FrameErrorInner::InvalidMemberSize {
                            kind: found,
                            size: 1,
                        } if *found == kind
                    ),
                    "{case} {kind:?}"
                );
            }
        }
    }

    #[test]
    fn header_errors_preserve_later_header_positions() {
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
            FrameErrorInner::InvalidPaxRecord {
                source: PaxError::InvalidRecords { .. },
            }
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
                inner: FrameErrorInner::InvalidPaxRecord {
                    source: PaxError::InvalidInteger { .. },
                },
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
        assert_eq!(member_header.kind, UstarKind::Regular);
        assert_eq!(
            data_frame(&frames, 1).completed_pax_records(),
            Some(
                [
                    PaxRecord::HdrCharset(PaxValue::Value(HdrCharset::Binary)),
                    PaxRecord::Path(PaxValue::Value(PaxString::Binary(
                        b"global".to_vec().into(),
                    ))),
                ]
                .as_slice()
            )
        );
        assert_eq!(
            data_frame(&frames, 3).completed_pax_records(),
            Some(
                [PaxRecord::Path(PaxValue::Value(PaxString::Binary(
                    b"local".to_vec().into()
                )))]
                .as_slice()
            )
        );

        let records = record("hdrcharset", "ISO-IR 8859 1 1998");
        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'x', &records);
        assert!(matches!(
            last_error_inner(&collect(bytes, BLOCK_SIZE)),
            FrameErrorInner::InvalidPaxRecord {
                source: PaxError::UnsupportedCharset { value },
            } if value == "ISO-IR 8859 1 1998"
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
