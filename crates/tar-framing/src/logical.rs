//! Member-oriented reading above the lossless physical frame stream.
//!
//! This API assembles PAX and GNU extension payloads with the ordinary members
//! they describe. Each member carries a compact borrowed [`Header`], and each
//! PAX member carries one unified [`PaxState`].

use std::{borrow::Cow, mem};

use tokio::io::AsyncRead;
use tokio_stream::StreamExt;

use crate::{
    ArchiveFormat, Block, FrameError, GnuKind, MemberKind, PaxKind, PaxRecord, PaxString, PaxValue,
    stream::{DataOwner, Frame, GnuFrame, HeaderFrame, PaxFrame, TarStream, parse_mode},
};

pub use crate::{PaxExtension, PaxState};

const PAYLOAD_DRAIN_CHUNK_BYTES: usize = 1024 * 1024;

/// A GNU long-name or long-link value needed to interpret a member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GnuMetadata {
    /// The absolute byte position of the GNU extension header block.
    pub position: u64,
    /// The meaningful metadata payload bytes, excluding tar padding.
    pub payload: Vec<u8>,
}

/// Extension metadata attached to one ordinary archive member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberExtensions {
    /// Unified pax metadata applicable to an ordinary ustar member.
    Pax(PaxState),
    /// GNU metadata applying to an ordinary GNU member.
    Gnu {
        /// Optional GNU long-name metadata.
        long_name: Option<GnuMetadata>,
        /// Optional GNU long-link metadata.
        long_link: Option<GnuMetadata>,
    },
}

/// Extracted ordinary-header metadata for one logical archive member.
///
/// Unlike [`HeaderFrame`], this type does not retain the lossless physical
/// header block. Its ordinary path and link-path fallbacks borrow reusable
/// storage owned by [`TarReader`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header<'a> {
    /// The absolute byte position of the ordinary member header block.
    pub position: u64,
    /// The selected archive family of this member header.
    pub format: ArchiveFormat,
    /// The member type identified by the header.
    pub kind: MemberKind,
    /// The size encoded directly in the member header field.
    pub declared_size: u64,
    /// The size after applying applicable pax `size` records.
    pub effective_size: u64,
    /// The number of payload bytes exposed through [`MemberPayload`].
    ///
    /// For pax hard links, the physical size may be nonzero and an applicable
    /// pax `size` record may override it. Every nonzero effective size is
    /// treated as payload because the format carries no separate marker.
    pub payload_size: u64,
    mode: [u8; 8],
    header_path: &'a [u8],
    link_name: &'a [u8],
}

impl Header<'_> {
    /// Decodes the ordinary header's numeric mode according to its archive family.
    pub fn mode(&self) -> Result<u64, FrameError> {
        parse_mode(self.position, self.format, self.mode)
    }

    /// Returns the header's claimed path for its member.
    ///
    /// For ustar headers, this is the combination of the `name` and `prefix`
    /// fields, i.e. `{prefix}/{name}`. For GNU headers, this is `name` alone.
    ///
    /// **IMPORTANT**: This is **not** guaranteed to be the fully effective path
    /// for a member. Most users should call [`MemberFrame::effective_path`].
    fn header_path(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.header_path)
    }

    /// Returns the header's claimed link name for its member.
    ///
    /// For both ustar and GNU headers, this is the `linkname` field.
    ///
    /// **IMPORTANT**: This is **not** guaranteed to be the fully effective
    /// link path for a member. Most users should call [`MemberFrame::effective_link_path`].
    fn link_name(&self) -> &[u8] {
        self.link_name
    }
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

/// An ordinary archive member and its streaming payload cursor.
pub struct MemberFrame<'a, R> {
    /// The ordinary member header.
    pub header: Header<'a>,
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
            MemberExtensions::Pax(state) => resolve_pax_text(
                self.header.position,
                state,
                "path",
                self.header.header_path(),
                |record| match record {
                    PaxRecord::Path(value) => Some(value),
                    _ => None,
                },
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
            MemberExtensions::Pax(state) => resolve_pax_text(
                self.header.position,
                state,
                "linkpath",
                Cow::Borrowed(self.header.link_name()),
                |record| match record {
                    PaxRecord::LinkPath(value) => Some(value),
                    _ => None,
                },
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
    reader: &'a mut PayloadReader<R>,
}

/// A logical reader that assembles physical frames into archive-level items.
///
/// Unlike [`TarStream`], this API attaches PAX or GNU extension metadata to the
/// ordinary member it describes. Each PAX member carries one [`PaxState`] with
/// effective metadata and newly encountered positioned extensions. Ordinary
/// header path and link-path fallbacks are copied into reusable storage and
/// borrowed by the returned [`Header`].
pub struct TarReader<R> {
    payload: PayloadReader<R>,
    header_storage: HeaderStorage,
}

/// Payload state kept separate so [`MemberPayload`] can borrow it mutably while
/// the logical [`Header`] borrows reusable header storage.
struct PayloadReader<R> {
    stream: TarStream<R>,
    remaining: u64,
    drain_buffer: Vec<u8>,
}

#[derive(Default)]
struct HeaderStorage {
    path: Vec<u8>,
    link_name: Vec<u8>,
}

impl HeaderStorage {
    fn update<'a>(&'a mut self, frame: &HeaderFrame) -> Header<'a> {
        frame.copy_header_path_into(&mut self.path);
        frame.copy_link_name_into(&mut self.link_name);
        Header {
            position: frame.position,
            format: frame.format,
            kind: frame.kind,
            declared_size: frame.declared_size,
            effective_size: frame.effective_size,
            payload_size: frame.payload_size,
            mode: frame.mode_bytes(),
            header_path: &self.path,
            link_name: &self.link_name,
        }
    }
}

impl<R> TarReader<R> {
    /// Creates a new logical reader from an uncompressed tar reader.
    pub fn new(reader: R) -> Self {
        Self {
            payload: PayloadReader {
                stream: TarStream::new(reader),
                remaining: 0,
                drain_buffer: Vec::new(),
            },
            header_storage: HeaderStorage::default(),
        }
    }
}

impl<R: AsyncRead + Unpin> TarReader<R> {
    /// Returns the next ordinary archive member.
    ///
    /// If the preceding member payload was not fully consumed, it is first
    /// drained and validated. Extension metadata is then consumed and attached
    /// before the next member is returned. Global pax updates not followed by
    /// an ordinary member are consumed and ignored.
    pub async fn next_frame(&mut self) -> Result<Option<MemberFrame<'_, R>>, FrameError> {
        self.payload.drain_payload().await?;

        let mut global_extensions: Vec<PaxExtension> = Vec::new();
        let mut local_extension = None;
        let mut long_name = None;
        let mut long_link = None;
        loop {
            let Some(frame) = self.next_physical_frame().await? else {
                return Ok(None);
            };
            match frame {
                Frame::Pax(PaxFrame { position, kind, .. }) => {
                    let extension = self.read_pax_extension(position, kind).await?;
                    match kind {
                        PaxKind::Global => global_extensions.push(extension),
                        PaxKind::Local => local_extension = Some(extension),
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
                    let extensions = match header.format {
                        ArchiveFormat::Pax => MemberExtensions::Pax(PaxState::new(
                            self.payload.stream.global_pax_records(),
                            global_extensions,
                            local_extension,
                        )),
                        ArchiveFormat::Gnu => MemberExtensions::Gnu {
                            long_name,
                            long_link,
                        },
                    };
                    self.payload.remaining = header.payload_size;
                    let header = self.header_storage.update(&header);
                    return Ok(Some(MemberFrame {
                        header,
                        extensions,
                        payload: MemberPayload {
                            reader: &mut self.payload,
                        },
                    }));
                }
                Frame::Data(frame) => {
                    return Err(FrameError::unexpected_order(
                        frame.position,
                        "extension header or ordinary member header",
                        "unattached payload data",
                    ));
                }
            }
        }
    }

    async fn next_physical_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        self.payload.stream.next().await.transpose()
    }

    async fn read_pax_extension(
        &mut self,
        position: u64,
        kind: PaxKind,
    ) -> Result<PaxExtension, FrameError> {
        loop {
            let Some(next) = self.next_physical_frame().await? else {
                return Err(self.unexpected_end("pax extension payload"));
            };
            match next {
                Frame::Data(data) if data.owner == DataOwner::Pax(kind) => {
                    if let Some(records) = data.into_completed_pax_records() {
                        return Ok(PaxExtension::new(position, kind, records));
                    }
                }
                other => {
                    return Err(self.unexpected_frame(&other, "pax extension payload"));
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
                        FrameError::arithmetic_overflow(
                            data.position,
                            "GNU metadata payload length",
                        )
                    })?;
                    remaining = remaining.checked_sub(len).ok_or_else(|| {
                        FrameError::unexpected_order(
                            data.position,
                            "bounded GNU metadata payload",
                            "oversized GNU metadata payload",
                        )
                    })?;
                    payload.extend_from_slice(&data.block[..data.len]);
                }
                other => {
                    return Err(self.unexpected_frame(&other, "GNU metadata payload"));
                }
            }
        }
        Ok(GnuMetadata {
            position: frame.position,
            payload,
        })
    }

    fn unexpected_end(&self, expected: &'static str) -> FrameError {
        FrameError::unexpected_eof(self.payload.stream.position(), expected)
    }

    fn unexpected_frame(&self, frame: &Frame, expected: &'static str) -> FrameError {
        let (position, found) = match frame {
            Frame::Pax(frame) => (frame.position, "pax extension header"),
            Frame::Gnu(frame) => (frame.position, "GNU metadata header"),
            Frame::Header(frame) => (frame.position, "ordinary member header"),
            Frame::Data(frame) => (frame.position, "payload data"),
        };
        FrameError::unexpected_order(position, expected, found)
    }
}

impl<R: AsyncRead + Unpin> PayloadReader<R> {
    async fn next_payload_block(&mut self) -> Result<Option<PayloadBlock>, FrameError> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let (position, block, len) = self.stream.read_member_block().await?;
        let payload_len = u64::try_from(len)
            .map_err(|_| FrameError::arithmetic_overflow(position, "member payload length"))?;
        self.remaining = self.remaining.checked_sub(payload_len).ok_or_else(|| {
            FrameError::unexpected_order(
                position,
                "bounded member payload",
                "oversized member payload",
            )
        })?;
        Ok(Some(PayloadBlock {
            position,
            block,
            len,
        }))
    }

    async fn next_payload_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, FrameError> {
        if self.remaining == 0 {
            buffer.clear();
            return Ok(false);
        }
        let position = self.stream.position();
        let len = self.stream.read_member_chunk(buffer, target_len).await?;
        let len = u64::try_from(len).map_err(|_| {
            FrameError::arithmetic_overflow(position, "member payload chunk length")
        })?;
        self.remaining = self.remaining.checked_sub(len).ok_or_else(|| {
            FrameError::unexpected_order(
                position,
                "bounded member payload",
                "oversized member payload chunk",
            )
        })?;
        Ok(true)
    }

    async fn drain_payload(&mut self) -> Result<(), FrameError> {
        let mut buffer = mem::take(&mut self.drain_buffer);
        let result = loop {
            match self
                .next_payload_chunk(&mut buffer, PAYLOAD_DRAIN_CHUNK_BYTES)
                .await
            {
                Ok(true) => {}
                Ok(false) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        self.drain_buffer = buffer;
        result
    }
}

impl<R: AsyncRead + Unpin> MemberPayload<'_, R> {
    /// Returns the next meaningful payload block, excluding final padding in `len`.
    pub async fn next_block(&mut self) -> Result<Option<PayloadBlock>, FrameError> {
        self.reader.next_payload_block().await
    }

    /// Reads validated payload bytes into a reusable chunk buffer.
    ///
    /// On success, the buffer's existing contents are replaced. Complete
    /// physical blocks are read directly into it until the chunk contains at
    /// least `target_len` bytes or the payload ends. The target is raised to one
    /// physical block when it is smaller, and final-block padding is removed
    /// before this returns. This preserves [`Self::next_block`] as the lossless
    /// interface while allowing higher-level consumers to amortize per-block
    /// bookkeeping and copies.
    pub async fn next_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, FrameError> {
        self.reader.next_payload_chunk(buffer, target_len).await
    }

    /// Discards and validates all remaining payload bytes using reusable storage.
    pub async fn skip(self) -> Result<(), FrameError> {
        self.reader.drain_payload().await
    }
}

fn resolve_pax_text<'a>(
    position: u64,
    state: &'a PaxState,
    keyword: &'static str,
    header_value: Cow<'a, [u8]>,
    select: fn(&PaxRecord) -> Option<&PaxValue<PaxString>>,
) -> Result<Cow<'a, [u8]>, FrameError> {
    if let Some(value) = state.effective_record(keyword).and_then(select) {
        return pax_value(position, keyword, value);
    }
    Ok(header_value)
}

/// Return the raw bytes of a pax record, erroring if the record is a tombstone
/// (i.e.) explicitly deleted.
fn pax_value<'a>(
    position: u64,
    keyword: &'static str,
    value: &'a PaxValue<PaxString>,
) -> Result<Cow<'a, [u8]>, FrameError> {
    match value {
        PaxValue::Value(PaxString::Utf8(value)) => Ok(Cow::Borrowed(value.as_bytes())),
        PaxValue::Value(PaxString::Binary(value)) => Ok(Cow::Borrowed(value)),
        // A pax value that has been explicitly deleted does *not*
        // result in a fallthrough to the corresponding ustar header value:
        //
        // "If a keyword in an extended header record (or in a -o option-
        // argument) overrides or deletes a corresponding field in the ustar
        // header block, pax shall ignore the contents of that header block
        // field."
        //
        // See: pax spec, "pax Extended Header"
        PaxValue::Deleted => Err(FrameError::deleted_pax_metadata(position, keyword)),
    }
}

fn parse_gnu_metadata(metadata: &GnuMetadata, kind: GnuKind) -> Result<&[u8], FrameError> {
    let terminator = metadata
        .payload
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| {
            FrameError::invalid_gnu_metadata(metadata.position, kind, "value is not NUL-terminated")
        })?;

    // TODO: Make this configurable through some kind of policy?
    // Might be overly strict in practice.
    if metadata.payload[terminator..].iter().any(|byte| *byte != 0) {
        return Err(FrameError::invalid_gnu_metadata(
            metadata.position,
            kind,
            "non-NUL bytes follow the terminator",
        ));
    }
    Ok(&metadata.payload[..terminator])
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncRead;

    use super::*;
    use crate::{
        BLOCK_SIZE, FrameError, FrameErrorInner, PaxRecord, PaxValue,
        header::{LINK_NAME_RANGE, MODE_RANGE, NAME_RANGE, PREFIX_RANGE, TYPEFLAG_OFFSET},
        stream::DataOwner,
        test_support::{
            ChunkedReader, append_block, append_gnu, append_payload, append_posix,
            append_terminator, gnu_header, header, ready, ready_ok, record, set_checksum,
        },
    };

    fn set_field(block: &mut Block, range: std::ops::Range<usize>, value: &[u8]) {
        block[range.clone()].fill(0);
        block[range.start..range.start + value.len()].copy_from_slice(value);
    }

    async fn next_member<R: AsyncRead + Unpin>(
        reader: &mut TarReader<R>,
    ) -> Result<MemberFrame<'_, R>, FrameError> {
        let Some(member) = reader.next_frame().await? else {
            panic!("expected logical member");
        };
        Ok(member)
    }

    fn pax_state<'a, R>(member: &'a MemberFrame<'_, R>) -> Option<&'a PaxState> {
        if let MemberExtensions::Pax(state) = &member.extensions {
            Some(state)
        } else {
            None
        }
    }

    #[test]
    fn exposes_ordinary_header_metadata_and_decodes_modes() {
        let mut ustar_header = header(b'2', 0);
        set_field(&mut ustar_header, NAME_RANGE, b"file");
        set_field(&mut ustar_header, PREFIX_RANGE, b"dir");
        set_field(&mut ustar_header, LINK_NAME_RANGE, b"target");
        ustar_header[MODE_RANGE].copy_from_slice(b"0000755\0");
        set_checksum(&mut ustar_header);

        ready_ok(async {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &ustar_header);
            append_terminator(&mut bytes);
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let member = next_member(&mut reader).await?;
            assert_eq!(member.header.format, ArchiveFormat::Pax);
            assert_eq!(member.header.header_path().as_ref(), b"dir/file");
            assert_eq!(member.header.link_name(), b"target");
            assert_eq!(member.header.mode()?, 0o755);
            assert_eq!(member.effective_path()?.as_ref(), b"dir/file");
            assert_eq!(member.effective_link_path()?.as_ref(), b"target");
            Ok(())
        });

        let mut gnu_header = gnu_header(b'0', 0);
        set_field(&mut gnu_header, NAME_RANGE, b"name");
        set_field(&mut gnu_header, PREFIX_RANGE, b"ignored");
        gnu_header[MODE_RANGE].fill(0);
        gnu_header[MODE_RANGE.start] = 0x80;
        gnu_header[MODE_RANGE.end - 2..MODE_RANGE.end].copy_from_slice(&[0x01, 0xed]);
        set_checksum(&mut gnu_header);

        ready_ok(async {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &gnu_header);
            append_terminator(&mut bytes);
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let member = next_member(&mut reader).await?;
            assert_eq!(member.header.format, ArchiveFormat::Gnu);
            assert_eq!(member.header.header_path().as_ref(), b"name");
            assert_eq!(member.header.mode()?, 0o755);
            Ok(())
        });
    }

    #[test]
    fn keeps_borrowed_header_metadata_available_while_streaming_payload() {
        let mut member_header = header(b'0', 1);
        set_field(&mut member_header, NAME_RANGE, b"file");
        set_field(&mut member_header, PREFIX_RANGE, b"dir");
        set_field(&mut member_header, LINK_NAME_RANGE, b"target");
        member_header[MODE_RANGE].copy_from_slice(b"0000755\0");
        set_checksum(&mut member_header);

        ready_ok(async {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &member_header);
            append_payload(&mut bytes, b"x");
            append_terminator(&mut bytes);
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let mut member = next_member(&mut reader).await?;

            assert!(member.payload.next_block().await?.is_some());
            assert_eq!(member.header.header_path().as_ref(), b"dir/file");
            assert_eq!(member.header.link_name(), b"target");
            assert_eq!(member.header.mode()?, 0o755);
            assert_eq!(member.effective_path()?.as_ref(), b"dir/file");
            assert_eq!(member.effective_link_path()?.as_ref(), b"target");
            Ok(())
        });
    }

    #[test]
    fn resolves_pax_path_precedence_and_deletions() {
        let mut global = record("path", "global");
        global.extend_from_slice(&record("linkpath", "global-link"));
        let mut local = record("path", "local");
        local.extend_from_slice(&record("linkpath", ""));
        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'g', &global);
        append_posix(&mut bytes, b'x', &local);
        append_block(&mut bytes, &header(b'2', 0));
        append_block(&mut bytes, &header(b'2', 0));
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            {
                let member = next_member(&mut reader).await?;
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
            let member = next_member(&mut reader).await?;
            assert_eq!(member.effective_path()?.as_ref(), b"global");
            assert_eq!(member.effective_link_path()?.as_ref(), b"global-link");
            Ok(())
        });
    }

    #[test]
    fn global_path_deletion_suppresses_the_physical_header_path() {
        let mut physical_header = header(b'0', 0);
        set_field(&mut physical_header, NAME_RANGE, b"physical");
        set_checksum(&mut physical_header);

        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'g', &record("path", "global"));
        append_block(&mut bytes, &header(b'0', 0));
        append_posix(&mut bytes, b'g', &record("path", ""));
        append_block(&mut bytes, &physical_header);
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            {
                let member = next_member(&mut reader).await?;
                assert_eq!(member.effective_path()?.as_ref(), b"global");
            }

            let member = next_member(&mut reader).await?;
            assert!(matches!(
                member.effective_path(),
                Err(FrameError {
                    inner: FrameErrorInner::DeletedPaxMetadata { keyword: "path" },
                    ..
                })
            ));
            let state = pax_state(&member).expect("expected pax member metadata");
            assert_eq!(
                state.effective_record("path"),
                Some(&PaxRecord::Path(PaxValue::Deleted))
            );
            let extensions = state.extensions().collect::<Vec<_>>();
            assert_eq!(extensions.len(), 1);
            assert!(matches!(
                extensions[0].records(),
                [PaxRecord::Path(PaxValue::Deleted)]
            ));
            Ok(())
        });
    }

    #[test]
    fn resolves_and_validates_gnu_metadata_lazily() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &gnu_header(b'L', 5));
        append_payload(&mut bytes, b"name\0");
        append_block(&mut bytes, &gnu_header(b'K', 5));
        append_payload(&mut bytes, b"link\0");
        append_block(&mut bytes, &gnu_header(b'2', 0));
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let member = next_member(&mut reader).await?;
            assert_eq!(member.effective_path()?.as_ref(), b"name");
            assert_eq!(member.effective_link_path()?.as_ref(), b"link");
            Ok(())
        });

        for (typeflag, payload, kind) in [
            (b'L', b"no-nul".as_slice(), GnuKind::LongName),
            (b'K', b"link\0bad".as_slice(), GnuKind::LongLink),
        ] {
            let mut bytes = Vec::new();
            append_gnu(&mut bytes, typeflag, payload);
            append_block(&mut bytes, &gnu_header(b'2', 0));
            append_terminator(&mut bytes);
            let result: Result<(), FrameError> = ready(async {
                let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
                let member = next_member(&mut reader).await?;
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
            let member = next_member(&mut reader).await?;
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
        append_posix(&mut bytes, b'g', &global);
        append_posix(&mut bytes, b'x', &local);
        append_block(&mut bytes, &header(b'0', 1));
        append_payload(&mut bytes, &[b'a'; BLOCK_SIZE]);
        append_payload(&mut bytes, b"b");
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, 17));
            {
                let mut member = next_member(&mut reader).await?;
                assert_eq!(member.header.effective_size, 513);
                let state = pax_state(&member).expect("expected pax member metadata");
                let extensions = state.extensions().collect::<Vec<_>>();
                assert_eq!(extensions.len(), 2);
                assert_eq!(extensions[0].position, 0);
                assert_eq!(extensions[0].kind, PaxKind::Global);
                assert_eq!(
                    extensions[0].records(),
                    [PaxRecord::Comment(PaxValue::Value("global".to_owned()))]
                );
                assert_eq!(extensions[1].position, (BLOCK_SIZE * 2) as u64);
                assert_eq!(extensions[1].kind, PaxKind::Local);
                assert_eq!(
                    state.effective_record("size"),
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
    }

    #[test]
    fn attaches_new_global_pax_updates_without_mutating_earlier_states() {
        let first = record("comment", "first");
        let second = record("gname", "second");
        let replacement = record("comment", "replacement");
        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'g', &first);
        append_posix(&mut bytes, b'g', &second);
        append_block(&mut bytes, &header(b'0', 0));
        append_block(&mut bytes, &header(b'0', 0));
        append_posix(&mut bytes, b'g', &replacement);
        append_block(&mut bytes, &header(b'0', 0));
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let first_state = {
                let member = next_member(&mut reader).await?;
                let state = pax_state(&member).expect("expected pax member metadata");
                let extensions = state.extensions().collect::<Vec<_>>();
                assert_eq!(extensions.len(), 2);
                assert_eq!(extensions[0].position, 0);
                assert_eq!(extensions[1].position, (BLOCK_SIZE * 2) as u64);
                assert_eq!(
                    state.effective_record("comment"),
                    Some(&PaxRecord::Comment(PaxValue::Value("first".to_owned())))
                );
                state.clone()
            };
            let member = next_member(&mut reader).await?;
            let state = pax_state(&member).expect("expected pax member metadata");
            assert_eq!(state.extensions().count(), 0);
            assert_eq!(
                state.effective_record("comment"),
                Some(&PaxRecord::Comment(PaxValue::Value("first".to_owned())))
            );
            drop(member);

            let member = next_member(&mut reader).await?;
            let state = pax_state(&member).expect("expected pax member metadata");
            let extensions = state.extensions().collect::<Vec<_>>();
            assert_eq!(extensions.len(), 1);
            assert_eq!(extensions[0].kind, PaxKind::Global);
            assert_eq!(
                state.effective_record("comment"),
                Some(&PaxRecord::Comment(PaxValue::Value(
                    "replacement".to_owned()
                )))
            );
            assert_eq!(
                first_state.effective_record("comment"),
                Some(&PaxRecord::Comment(PaxValue::Value("first".to_owned())))
            );
            Ok(())
        });
    }

    #[test]
    fn streams_member_payload_in_reusable_chunks() {
        let payload = (0..BLOCK_SIZE * 3 + 7)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        append_posix(&mut bytes, b'0', &payload);
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, 17));
            let mut member = next_member(&mut reader).await?;
            let mut chunk = vec![b'x'; BLOCK_SIZE * 2];
            assert!(
                member
                    .payload
                    .next_chunk(&mut chunk, BLOCK_SIZE + 1)
                    .await?
            );
            assert_eq!(chunk, payload[..BLOCK_SIZE * 2]);
            assert!(
                member
                    .payload
                    .next_chunk(&mut chunk, BLOCK_SIZE + 1)
                    .await?
            );
            assert_eq!(chunk, payload[BLOCK_SIZE * 2..]);
            assert!(
                !member
                    .payload
                    .next_chunk(&mut chunk, BLOCK_SIZE + 1)
                    .await?
            );
            assert!(chunk.is_empty());
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });
    }

    #[test]
    fn reports_reusable_chunk_errors_at_physical_block_boundaries() {
        #[derive(Clone, Copy, Debug)]
        enum ExpectedError {
            TruncatedPayload,
            IncompleteBlock,
        }

        for (expected, trailing_byte) in [
            (ExpectedError::TruncatedPayload, None),
            (ExpectedError::IncompleteBlock, Some(b'x')),
        ] {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &header(b'0', (BLOCK_SIZE + 1) as u64));
            append_payload(&mut bytes, b"payload");
            if let Some(trailing_byte) = trailing_byte {
                bytes.push(trailing_byte);
            }
            let error = ready(async {
                let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
                let Ok(Some(mut member)) = reader.next_frame().await else {
                    panic!("expected member");
                };
                member
                    .payload
                    .next_chunk(&mut Vec::new(), BLOCK_SIZE * 2)
                    .await
            });
            let Err(FrameError { position, inner }) = &error else {
                panic!("{expected:?}: expected error, got {error:?}");
            };
            assert_eq!(*position, (BLOCK_SIZE * 2) as u64, "{expected:?}");
            assert!(
                matches!(
                    (expected, inner),
                    (
                        ExpectedError::TruncatedPayload,
                        FrameErrorInner::TruncatedPayload {
                            owner: DataOwner::Member,
                            remaining: 1,
                        },
                    ) | (
                        ExpectedError::IncompleteBlock,
                        FrameErrorInner::IncompleteBlock { read: 1 },
                    )
                ),
                "{expected:?}: {error:?}"
            );
        }
    }

    #[test]
    fn groups_gnu_metadata_with_its_member() {
        let mut bytes = Vec::new();
        append_block(&mut bytes, &gnu_header(b'L', 5));
        append_payload(&mut bytes, b"name\0");
        append_block(&mut bytes, &gnu_header(b'K', 5));
        append_payload(&mut bytes, b"link\0");
        append_block(&mut bytes, &gnu_header(b'2', 0));
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let mut member = next_member(&mut reader).await?;
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
    }

    #[test]
    fn preserves_multiblock_gnu_metadata_payloads() {
        let mut long_name = vec![b'n'; BLOCK_SIZE * 2 + 37];
        long_name.push(0);
        let mut long_link = vec![b'l'; BLOCK_SIZE + 19];
        long_link.push(0);

        let mut bytes = Vec::new();
        append_gnu(&mut bytes, b'L', &long_name);
        append_gnu(&mut bytes, b'K', &long_link);
        append_block(&mut bytes, &gnu_header(b'2', 0));
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, 19));
            let member = next_member(&mut reader).await?;
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
    }

    #[test]
    fn handles_empty_archives_and_trailing_global_pax() {
        let mut empty = Vec::new();
        append_terminator(&mut empty);
        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(empty, BLOCK_SIZE));
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });

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

        let mut global = Vec::new();
        append_posix(&mut global, b'g', &record("comment", "metadata"));
        append_posix(&mut global, b'g', &record("gname", "group"));
        append_terminator(&mut global);
        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(global, BLOCK_SIZE));
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });

        let mut malformed_global = Vec::new();
        append_posix(&mut malformed_global, b'g', b"invalid");
        append_terminator(&mut malformed_global);
        let error: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(malformed_global, BLOCK_SIZE));
            reader.next_frame().await.map(|_| ())
        });
        assert!(matches!(
            error,
            Err(FrameError {
                position: 0,
                inner: FrameErrorInner::InvalidPaxRecords { .. },
            })
        ));
    }

    #[test]
    fn skips_unread_payload_before_advancing() {
        for payload_len in [BLOCK_SIZE + 1, PAYLOAD_DRAIN_CHUNK_BYTES + 7] {
            let payload = vec![b'a'; payload_len];
            let mut bytes = Vec::new();
            append_posix(&mut bytes, b'0', &payload);
            append_block(&mut bytes, &header(b'0', 0));
            append_terminator(&mut bytes);

            ready_ok(async {
                let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
                {
                    let member = next_member(&mut reader).await?;
                    member.payload.skip().await?;
                }
                let member = next_member(&mut reader).await?;
                assert_eq!(member.header.payload_size, 0);
                drop(member);
                assert!(reader.next_frame().await?.is_none());
                Ok(())
            });
        }

        let mut auto_bytes = Vec::new();
        append_block(&mut auto_bytes, &header(b'0', 1));
        append_payload(&mut auto_bytes, b"a");
        append_block(&mut auto_bytes, &header(b'0', 0));
        append_terminator(&mut auto_bytes);
        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(auto_bytes, BLOCK_SIZE));
            let first = next_member(&mut reader).await?;
            drop(first);
            assert!(reader.next_frame().await?.is_some());
            Ok(())
        });
    }

    #[test]
    fn reports_truncated_payload_when_read_or_skipped() {
        #[derive(Clone, Copy, Debug)]
        enum Operation {
            Read,
            ExplicitSkip,
            AutomaticSkip,
        }

        for operation in [
            Operation::Read,
            Operation::ExplicitSkip,
            Operation::AutomaticSkip,
        ] {
            let result: Result<(), FrameError> = ready(async {
                let mut reader =
                    TarReader::new(ChunkedReader::new(header(b'0', 1).to_vec(), BLOCK_SIZE));
                let Ok(Some(mut member)) = reader.next_frame().await else {
                    panic!("expected member");
                };
                match operation {
                    Operation::Read => member.payload.next_block().await.map(|_| ()),
                    Operation::ExplicitSkip => member.payload.skip().await,
                    Operation::AutomaticSkip => {
                        drop(member);
                        reader.next_frame().await.map(|_| ())
                    }
                }
            });
            assert!(
                matches!(
                    result,
                    Err(FrameError {
                        inner: FrameErrorInner::TruncatedPayload {
                            owner: DataOwner::Member,
                            ..
                        },
                        ..
                    })
                ),
                "{operation:?}"
            );
        }
    }
}
