//! Member-oriented reading above the lossless physical frame stream.
//!
//! This API assembles local pax and GNU extension payloads with the ordinary
//! member they describe, while global pax updates remain independent items.

use std::borrow::Cow;

use tokio::io::AsyncRead;
use tokio_stream::StreamExt;

use crate::{
    ArchiveFormat, Block, FrameError, FrameErrorInner, GnuKind, MemberKind, PaxKind, PaxRecord,
    PaxString, PaxValue,
    stream::{DataOwner, Frame, GnuFrame, PaxFrame, TarStream, parse_number},
};

const NAME_RANGE: std::ops::Range<usize> = 0..100;
const MODE_RANGE: std::ops::Range<usize> = 100..108;
const LINK_NAME_RANGE: std::ops::Range<usize> = 157..257;
const PREFIX_RANGE: std::ops::Range<usize> = 345..500;

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
    pub block: Block,
    /// The selected archive family of this member header.
    pub format: ArchiveFormat,
    /// The member type identified by the header.
    pub kind: MemberKind,
    /// The size encoded directly in the member header field.
    pub declared_size: u64,
    /// The size after applying applicable pax `size` records.
    pub effective_size: u64,
    /// The meaningful payload size belonging to this member.
    pub payload_size: u64,
}

impl MemberHeader {
    /// Returns the ordinary header's member-name bytes, trimmed at the first NUL.
    pub fn name(&self) -> &[u8] {
        trim_nul(&self.block[NAME_RANGE])
    }

    /// Returns the ordinary header's prefix bytes, trimmed at the first NUL.
    pub fn prefix(&self) -> &[u8] {
        trim_nul(&self.block[PREFIX_RANGE])
    }

    /// Returns the ordinary member path before extension metadata is applied.
    ///
    /// For ustar headers, this is the concatenation of the prefix and name fields.
    /// For GNU headers, this is just the name field.
    ///
    /// **IMPORTANT**: This path is **not** guaranteed to be meaningful, valid, or
    /// correct in the presence of pax or GNU metadata. Some tar encoders will place
    /// a sentinel value in these fields. Unless you're writing a forensic tar
    /// inspector, you probably want [`MemberFrame::effective_path`] instead.
    pub fn header_path(&self) -> Cow<'_, [u8]> {
        let name = self.name();
        if self.format == ArchiveFormat::Gnu {
            return Cow::Borrowed(name);
        }
        let prefix = self.prefix();
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

    /// Returns the ordinary header's link-name bytes, trimmed at the first NUL.
    pub fn link_name(&self) -> &[u8] {
        trim_nul(&self.block[LINK_NAME_RANGE])
    }

    /// Decodes the ordinary header's numeric mode according to its archive family.
    pub fn mode(&self) -> Result<u64, FrameError> {
        let bytes: [u8; 8] = self.block[MODE_RANGE]
            .try_into()
            .expect("fixed header range");
        parse_number(self.format, &bytes).ok_or_else(|| {
            FrameError::at(self.position, FrameErrorInner::InvalidMode { found: bytes })
        })
    }
}

/// Extension metadata attached to one ordinary archive member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberExtensions {
    /// pax state applicable to an ordinary ustar member.
    Pax {
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
    pub block: Block,
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

impl<R> MemberFrame<'_, R> {
    /// Returns the effective member path after applying pax or GNU metadata.
    ///
    /// An explicit pax deletion is an error because it also removes the
    /// ordinary-header fallback required to identify this member.
    pub fn effective_path(&self) -> Result<Cow<'_, [u8]>, FrameError> {
        match &self.extensions {
            MemberExtensions::Pax {
                global_records,
                local,
            } => resolve_pax_text(
                self.header.position,
                global_records,
                local.as_ref(),
                "path",
                self.header.header_path(),
                path_value,
            ),
            MemberExtensions::Gnu { long_name, .. } => match long_name {
                Some(metadata) => Ok(Cow::Borrowed(parse_gnu_metadata(
                    metadata,
                    GnuKind::LongName,
                )?)),
                None => Ok(self.header.header_path()),
            },
        }
    }

    /// Returns the effective member link target after applying pax or GNU metadata.
    ///
    /// An explicit pax deletion is an error because it also removes the
    /// ordinary-header fallback required to identify a link target.
    pub fn effective_link_path(&self) -> Result<Cow<'_, [u8]>, FrameError> {
        match &self.extensions {
            MemberExtensions::Pax {
                global_records,
                local,
            } => resolve_pax_text(
                self.header.position,
                global_records,
                local.as_ref(),
                "linkpath",
                Cow::Borrowed(self.header.link_name()),
                link_path_value,
            ),
            MemberExtensions::Gnu { long_link, .. } => match long_link {
                Some(metadata) => Ok(Cow::Borrowed(parse_gnu_metadata(
                    metadata,
                    GnuKind::LongLink,
                )?)),
                None => Ok(Cow::Borrowed(self.header.link_name())),
            },
        }
    }
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
                        ArchiveFormat::Pax => MemberExtensions::Pax {
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
                        format,
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

fn resolve_pax_text<'a>(
    position: u64,
    global_records: &'a [PaxRecord],
    local: Option<&'a PaxMetadata>,
    keyword: &'static str,
    header_value: Cow<'a, [u8]>,
    select: fn(&PaxRecord) -> Option<&PaxValue<PaxString>>,
) -> Result<Cow<'a, [u8]>, FrameError> {
    let value = local
        .and_then(|local| local.records.iter().rev().find_map(select))
        .or_else(|| global_records.iter().rev().find_map(select));
    if let Some(value) = value {
        return pax_value(position, keyword, value);
    }
    Ok(header_value)
}

fn path_value(record: &PaxRecord) -> Option<&PaxValue<PaxString>> {
    if let PaxRecord::Path(value) = record {
        Some(value)
    } else {
        None
    }
}

fn link_path_value(record: &PaxRecord) -> Option<&PaxValue<PaxString>> {
    if let PaxRecord::LinkPath(value) = record {
        Some(value)
    } else {
        None
    }
}

/// Return the raw bytes of a pax record, erroring if the record is a tombstone
/// (i.e.) explicitly deleted.
fn pax_value<'a>(
    position: u64,
    keyword: &'static str,
    value: &'a PaxValue<PaxString>,
) -> Result<Cow<'a, [u8]>, FrameError> {
    match value {
        PaxValue::Value(value) => Ok(Cow::Borrowed(value.as_bytes())),
        // A pax value that has been explicitly deleted does *not*
        // result in a fallthrough to the corresponding ustar header value:
        //
        // "If a keyword in an extended header record (or in a -o option-
        // argument) overrides or deletes a corresponding field in the ustar
        // header block, pax shall ignore the contents of that header block
        // field."
        //
        // See: pax spec, "pax Extended Header"
        PaxValue::Deleted => Err(FrameError::at(
            position,
            FrameErrorInner::DeletedPaxMetadata { keyword },
        )),
    }
}

fn parse_gnu_metadata(metadata: &GnuMetadata, kind: GnuKind) -> Result<&[u8], FrameError> {
    let terminator = metadata
        .payload
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| {
            FrameError::at(
                metadata.position,
                FrameErrorInner::InvalidGnuMetadata {
                    kind,
                    reason: "value is not NUL-terminated",
                },
            )
        })?;

    // TODO: Make this configurable through some kind of policy?
    // Might be overly strict in practice.
    if metadata.payload[terminator..].iter().any(|byte| *byte != 0) {
        return Err(FrameError::at(
            metadata.position,
            FrameErrorInner::InvalidGnuMetadata {
                kind,
                reason: "non-NUL bytes follow the terminator",
            },
        ));
    }
    Ok(&metadata.payload[..terminator])
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..end]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BLOCK_SIZE, FrameError, FrameErrorInner, PaxRecord, PaxValue,
        stream::{DataOwner, TYPEFLAG_OFFSET},
        test_support::{
            ChunkedReader, append_block, append_payload, append_terminator, data, gnu_header,
            header, ready, record, set_checksum,
        },
    };

    fn set_field(block: &mut Block, range: std::ops::Range<usize>, value: &[u8]) {
        block[range.clone()].fill(0);
        block[range.start..range.start + value.len()].copy_from_slice(value);
    }

    #[test]
    fn exposes_ordinary_header_metadata_and_decodes_modes() {
        let mut ustar_header = header(b'2', 0);
        set_field(&mut ustar_header, NAME_RANGE, b"file");
        set_field(&mut ustar_header, PREFIX_RANGE, b"dir");
        set_field(&mut ustar_header, LINK_NAME_RANGE, b"target");
        ustar_header[MODE_RANGE].copy_from_slice(b"0000755\0");
        set_checksum(&mut ustar_header);

        let ustar_result: Result<(), FrameError> = ready(async {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &ustar_header);
            append_terminator(&mut bytes);
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                panic!("expected ustar member");
            };
            assert_eq!(member.header.format, ArchiveFormat::Pax);
            assert_eq!(member.header.name(), b"file");
            assert_eq!(member.header.prefix(), b"dir");
            assert_eq!(member.header.header_path().as_ref(), b"dir/file");
            assert_eq!(member.header.link_name(), b"target");
            assert_eq!(member.header.mode()?, 0o755);
            assert_eq!(member.effective_path()?.as_ref(), b"dir/file");
            assert_eq!(member.effective_link_path()?.as_ref(), b"target");
            Ok(())
        });
        assert!(ustar_result.is_ok());

        let mut gnu_header = gnu_header(b'0', 0);
        set_field(&mut gnu_header, NAME_RANGE, b"name");
        set_field(&mut gnu_header, PREFIX_RANGE, b"ignored");
        gnu_header[MODE_RANGE].fill(0);
        gnu_header[MODE_RANGE.start] = 0x80;
        gnu_header[MODE_RANGE.end - 2..MODE_RANGE.end].copy_from_slice(&[0x01, 0xed]);
        set_checksum(&mut gnu_header);

        let gnu_result: Result<(), FrameError> = ready(async {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &gnu_header);
            append_terminator(&mut bytes);
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                panic!("expected GNU member");
            };
            assert_eq!(member.header.format, ArchiveFormat::Gnu);
            assert_eq!(member.header.header_path().as_ref(), b"name");
            assert_eq!(member.header.mode()?, 0o755);
            Ok(())
        });
        assert!(gnu_result.is_ok());
    }

    #[test]
    fn resolves_pax_path_precedence_and_deletions() {
        let mut global = record("path", "global");
        global.extend_from_slice(&record("linkpath", "global-link"));
        let mut local = record("path", "local");
        local.extend_from_slice(&record("linkpath", ""));
        let mut bytes = Vec::new();
        append_block(&mut bytes, &header(b'g', global.len() as u64));
        append_payload(&mut bytes, &global);
        append_block(&mut bytes, &header(b'x', local.len() as u64));
        append_payload(&mut bytes, &local);
        append_block(&mut bytes, &header(b'2', 0));
        append_block(&mut bytes, &header(b'2', 0));
        append_terminator(&mut bytes);

        let result: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            assert!(matches!(
                reader.next_frame().await?,
                Some(LogicalFrame::GlobalPax(_))
            ));
            {
                let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                    panic!("expected local pax member");
                };
                assert_eq!(member.effective_path()?.as_ref(), b"local");
                assert!(matches!(
                    member.effective_link_path(),
                    Err(FrameError {
                        position: 2048,
                        inner: FrameErrorInner::DeletedPaxMetadata {
                            keyword: "linkpath"
                        },
                    })
                ));
            }
            let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                panic!("expected global pax member");
            };
            assert_eq!(member.effective_path()?.as_ref(), b"global");
            assert_eq!(member.effective_link_path()?.as_ref(), b"global-link");
            Ok(())
        });
        assert!(result.is_ok());
    }

    #[test]
    fn resolves_and_validates_gnu_metadata_lazily() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &gnu_header(b'L', 5));
        append_block(&mut bytes, &data(b"name\0"));
        append_block(&mut bytes, &gnu_header(b'K', 5));
        append_block(&mut bytes, &data(b"link\0"));
        append_block(&mut bytes, &gnu_header(b'2', 0));
        append_terminator(&mut bytes);

        let resolved_result: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                panic!("expected GNU member");
            };
            assert_eq!(member.effective_path()?.as_ref(), b"name");
            assert_eq!(member.effective_link_path()?.as_ref(), b"link");
            Ok(())
        });
        assert!(resolved_result.is_ok());

        for (typeflag, payload, kind) in [
            (b'L', b"no-nul".as_slice(), GnuKind::LongName),
            (b'K', b"link\0bad".as_slice(), GnuKind::LongLink),
        ] {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &gnu_header(typeflag, payload.len() as u64));
            append_payload(&mut bytes, payload);
            append_block(&mut bytes, &gnu_header(b'2', 0));
            append_terminator(&mut bytes);
            let result: Result<(), FrameError> = ready(async {
                let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
                let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                    panic!("expected GNU member before metadata interpretation");
                };
                match kind {
                    GnuKind::LongName => member.effective_path().map(|_| ()),
                    GnuKind::LongLink => member.effective_link_path().map(|_| ()),
                }
            });
            assert!(matches!(
                result,
                Err(FrameError {
                    position: 0,
                    inner: FrameErrorInner::InvalidGnuMetadata { kind: found, .. },
                }) if found == kind
            ));
        }
    }

    #[test]
    fn rejects_invalid_member_modes_when_decoded() {
        let mut header = header(b'0', 0);
        header[MODE_RANGE].copy_from_slice(b"0000080\0");
        set_checksum(&mut header);
        let result: Result<(), FrameError> = ready(async {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &header);
            append_terminator(&mut bytes);
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                panic!("expected member before mode interpretation");
            };
            member.header.mode().map(|_| ())
        });
        assert!(matches!(
            result,
            Err(FrameError {
                position: 0,
                inner: FrameErrorInner::InvalidMode { .. },
            })
        ));
    }

    #[test]
    fn groups_pax_metadata_and_streams_member_payload() {
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
            assert_eq!(global_header.position, 0);
            assert_eq!(
                global_header.records,
                [PaxRecord::Comment(PaxValue::Value("global".to_owned()))]
            );

            {
                let Some(LogicalFrame::Member(mut member)) = reader.next_frame().await? else {
                    panic!("expected logical member");
                };
                assert_eq!(member.header.effective_size, 513);
                let MemberExtensions::Pax {
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
    fn groups_gnu_metadata_with_its_member() {
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
    fn preserves_multiblock_gnu_metadata_payloads() {
        let mut long_name = vec![b'n'; BLOCK_SIZE * 2 + 37];
        long_name.push(0);
        let mut long_link = vec![b'l'; BLOCK_SIZE + 19];
        long_link.push(0);

        let mut bytes = Vec::new();
        append_block(&mut bytes, &gnu_header(b'L', long_name.len() as u64));
        append_payload(&mut bytes, &long_name);
        append_block(&mut bytes, &gnu_header(b'K', long_link.len() as u64));
        append_payload(&mut bytes, &long_link);
        append_block(&mut bytes, &gnu_header(b'2', 0));
        append_terminator(&mut bytes);

        let result: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, 19));
            let Some(LogicalFrame::Member(member)) = reader.next_frame().await? else {
                panic!("expected GNU member");
            };
            let MemberExtensions::Gnu {
                long_name: Some(name_metadata),
                long_link: Some(link_metadata),
            } = &member.extensions
            else {
                panic!("expected GNU extensions");
            };
            assert_eq!(name_metadata.position, 0);
            assert_eq!(name_metadata.payload, long_name);
            assert_eq!(link_metadata.position, (BLOCK_SIZE * 4) as u64);
            assert_eq!(link_metadata.payload, long_link);
            member.payload.skip().await?;
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });
        assert!(result.is_ok());
    }

    #[test]
    fn handles_empty_archives_and_rejects_dangling_metadata() {
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
    fn skips_unread_payload_before_advancing() {
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
    fn reports_truncated_payload_when_read_or_skipped() {
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
