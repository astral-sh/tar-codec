//! Member-oriented reading above the lossless physical frame stream.
//!
//! This API assembles local pax and GNU extension payloads with the ordinary
//! member they describe, while global pax updates remain independent items.

use tokio::io::AsyncRead;
use tokio_stream::StreamExt;

use crate::{
    ArchiveFormat, BLOCK_SIZE, FrameError, FrameErrorInner, GnuKind, MemberKind, PaxKind,
    PaxRecord,
    physical::{DataOwner, Frame, GnuFrame, PaxFrame, TarStream},
};

/// Parsed pax metadata needed to interpret a logical archive item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaxMetadata {
    /// The absolute byte position of the pax extension header block.
    pub position: u64,
    /// Parsed pax records in archive order.
    pub records: Vec<PaxRecord>,
}

/// A GNU long-name or long-link value needed to interpret a member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GnuMetadata {
    /// The absolute byte position of the GNU extension header block.
    pub position: u64,
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
        /// Local pax metadata applying only to this member.
        local: Option<PaxMetadata>,
    },
    /// GNU metadata applying to an ordinary GNU member.
    Gnu {
        /// Optional GNU long-name metadata.
        long_name: Option<GnuMetadata>,
        /// Optional GNU long-link metadata.
        long_link: Option<GnuMetadata>,
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
///
/// Member items intentionally retain their raw ordinary header block for
/// higher-level decoding, so this enum favors lossless context over compact
/// inline representation.
#[expect(
    clippy::large_enum_variant,
    reason = "logical members retain their lossless ordinary header block"
)]
pub enum LogicalFrame<'a, R> {
    /// A standalone global pax update.
    GlobalPax(PaxMetadata),
    /// An ordinary archive member with attached local metadata and payload.
    Member(MemberFrame<'a, R>),
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
                    let kind = frame.kind;
                    let metadata = self.read_pax_metadata(frame).await?;
                    match kind {
                        PaxKind::Global => {
                            return Ok(Some(LogicalFrame::GlobalPax(metadata)));
                        }
                        PaxKind::Local => local_pax = Some(metadata),
                    }
                }
                Frame::Gnu(frame) => {
                    let kind = frame.kind;
                    let metadata = self.read_gnu_metadata(frame).await?;
                    match kind {
                        GnuKind::LongName => long_name = Some(metadata),
                        GnuKind::LongLink => long_link = Some(metadata),
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
                    return Ok(Some(LogicalFrame::Member(MemberFrame {
                        header,
                        extensions,
                        payload: MemberPayload { reader: self },
                    })));
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

    async fn read_pax_metadata(&mut self, frame: PaxFrame) -> Result<PaxMetadata, FrameError> {
        loop {
            let Some(next) = self.next_physical_frame().await? else {
                return Err(self.unexpected_end("pax extension payload"));
            };
            match next {
                Frame::Data(data) if data.owner == DataOwner::Pax(frame.kind) => {
                    if let Some(records) = data.completed_pax_records {
                        return Ok(PaxMetadata {
                            position: frame.position,
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

    async fn read_gnu_metadata(&mut self, frame: GnuFrame) -> Result<GnuMetadata, FrameError> {
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
        Ok(GnuMetadata {
            position: frame.position,
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
                self.stream.position(),
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
            self.stream.position(),
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
