//! Member-oriented reading above the lossless physical frame stream.
//!
//! This API assembles PAX and GNU extension payloads with the ordinary members
//! they describe. Each member carries a compact borrowed [`Header`], and each
//! PAX member carries one unified [`PaxState`].

use std::{borrow::Cow, mem, ops::Range};

use tokio::io::AsyncRead;

use crate::{
    ArchiveFormat, Block, FrameError, FrameErrorInner, GnuKind, PaxKeyword, PaxKind, PaxRecord,
    PaxString, PaxValue, UstarKind,
    header::{GNAME_RANGE, LINK_NAME_RANGE, UNAME_RANGE},
    pax::GlobalPaxRecords,
    stream::{DataFrame, DataOwner, Frame, HeaderFrame, TarStream},
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
pub enum MemberExtensions<'a> {
    /// Unified pax metadata applicable to an ordinary ustar member, borrowing
    /// effective global values from the logical reader.
    Pax(PaxState<'a>),
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
    pub kind: UstarKind,
    /// The size encoded directly in the member header field.
    pub declared_size: u64,
    /// The size after applying applicable pax `size` records.
    ///
    /// This is also the number of payload bytes exposed through
    /// [`MemberPayload`]. Member kinds that cannot carry payload are rejected
    /// when either their declared or effective size is nonzero.
    pub effective_size: u64,
    /// Permission and mode bits decoded from the ordinary header, if present.
    ///
    /// Note that pax only defines the semantics of the lower 12 bits of this
    /// field. Higher bits may or may not be set, and have no assigned semantics.
    ///
    /// This is [`None`] only when the field is wholly NUL and the framing policy
    /// permits missing numeric metadata.
    pub mode: Option<u64>,
    /// Numeric user identifier from the ordinary header, if present.
    ///
    /// This is [`None`] only when the field is wholly NUL and the framing policy
    /// permits missing numeric metadata.
    ///
    /// Applicable pax metadata may override or delete this fallback.
    pub uid: Option<u64>,
    /// Numeric group identifier from the ordinary header, if present.
    ///
    /// This is [`None`] only when the field is wholly NUL and the framing policy
    /// permits missing numeric metadata.
    ///
    /// Applicable pax metadata may override or delete this fallback.
    pub gid: Option<u64>,
    /// Modification time in seconds from the ordinary header, if present.
    ///
    /// This is [`None`] only when the field is wholly NUL and the framing policy
    /// permits missing numeric metadata.
    ///
    /// Applicable pax metadata may override or delete this fallback.
    pub mtime: Option<u64>,
    /// User name bytes from the ordinary header, empty if absent or unusable.
    ///
    /// Applicable pax metadata may override or delete this fallback.
    pub uname: &'a [u8],
    /// Group name bytes from the ordinary header, empty if absent or unusable.
    ///
    /// Applicable pax metadata may override or delete this fallback.
    pub gname: &'a [u8],
    header_path: &'a [u8],
    link_name: &'a [u8],
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
    pub extensions: MemberExtensions<'a>,
    /// A cursor over the member payload bytes.
    pub payload: MemberPayload<'a, R>,
}

impl<R> MemberFrame<'_, R> {
    /// Returns the effective member path after applying pax or GNU metadata.
    ///
    /// An explicit pax deletion is an error because it also removes the
    /// ordinary-header fallback required to identify this member. Empty paths
    /// and paths containing embedded NUL bytes are also rejected.
    pub fn effective_path(&self) -> Result<Cow<'_, [u8]>, FrameError> {
        let path = effective_member_path(&self.header, &self.extensions)?;
        if path.is_empty() {
            return Err(FrameError::at(
                self.header.position,
                FrameErrorInner::EmptyMemberPath,
            ));
        }
        reject_nul(self.header.position, "path", path.as_ref())?;
        Ok(path)
    }

    /// Returns the effective member link target after applying pax or GNU metadata.
    ///
    /// An explicit pax deletion is an error because it also removes the
    /// ordinary-header fallback required to identify a link target. Link
    /// targets containing embedded NUL bytes are also rejected.
    pub fn effective_link_path(&self) -> Result<Cow<'_, [u8]>, FrameError> {
        let path = match &self.extensions {
            MemberExtensions::Pax(state) => resolve_pax_text(
                self.header.position,
                state,
                &PaxKeyword::LinkPath,
                "linkpath",
                Cow::Borrowed(self.header.link_name),
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
                None => Ok(Cow::Borrowed(self.header.link_name)),
            },
        }?;
        reject_nul(self.header.position, "link path", path.as_ref())?;
        Ok(path)
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
    // Keep the logical effective state outside `payload` so a returned
    // `PaxState` can borrow it while `MemberPayload` mutably borrows only the
    // independent payload machinery. `TarStream` maintains its own physical
    // copy for framing decisions.
    global_pax_records: Option<GlobalPaxRecords>,
    payload: PayloadReader<R>,
    header_storage: HeaderStorage,
    pending_extensions: PendingExtensions,
    extension_payload: Option<ExtensionPayload>,
}

/// Payload state kept separate so [`MemberPayload`] can borrow it mutably while
/// the logical [`Header`] borrows reusable header storage.
struct PayloadReader<R> {
    stream: TarStream<R>,
    remaining: u64,
    drain_buffer: Vec<u8>,
}

/// Logical member metadata retained across cancellation of [`TarReader::next_frame`].
#[derive(Default)]
struct PendingExtensions {
    global_pax: Vec<PaxExtension>,
    local_pax: Option<PaxExtension>,
    gnu_long_name: Option<GnuMetadata>,
    gnu_long_link: Option<GnuMetadata>,
}

impl PendingExtensions {
    fn set_gnu(&mut self, kind: GnuKind, metadata: GnuMetadata) {
        *match kind {
            GnuKind::LongName => &mut self.gnu_long_name,
            GnuKind::LongLink => &mut self.gnu_long_link,
        } = Some(metadata);
    }
}

/// An extension payload being assembled across physical frames.
enum ExtensionPayload {
    Pax {
        position: u64,
        kind: PaxKind,
    },
    Gnu {
        position: u64,
        kind: GnuKind,
        remaining: u64,
        payload: Vec<u8>,
    },
}

#[derive(Default)]
struct HeaderStorage {
    path: Vec<u8>,
    link_name: Vec<u8>,
    uname: Vec<u8>,
    gname: Vec<u8>,
}

impl HeaderStorage {
    fn update<'a>(&'a mut self, frame: &HeaderFrame) -> Header<'a> {
        frame.copy_header_path_into(&mut self.path);
        copy_string_field_into(&frame.block, LINK_NAME_RANGE, &mut self.link_name);
        copy_string_field_into(&frame.block, UNAME_RANGE, &mut self.uname);
        copy_string_field_into(&frame.block, GNAME_RANGE, &mut self.gname);
        Header {
            position: frame.position,
            format: frame.format,
            kind: frame.kind,
            declared_size: frame.declared_size,
            effective_size: frame.effective_size,
            mode: frame.mode,
            uid: frame.uid,
            gid: frame.gid,
            mtime: frame.mtime,
            uname: &self.uname,
            gname: &self.gname,
            header_path: &self.path,
            link_name: &self.link_name,
        }
    }
}

fn copy_string_field_into(block: &Block, range: Range<usize>, destination: &mut Vec<u8>) {
    let field = &block[range];
    let len = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    destination.clear();
    destination.extend_from_slice(&field[..len]);
}

impl<R> TarReader<R> {
    /// Creates a new logical reader from an uncompressed tar reader.
    pub fn new(reader: R) -> Self {
        Self {
            global_pax_records: None,
            payload: PayloadReader {
                stream: TarStream::new(reader),
                remaining: 0,
                drain_buffer: Vec::new(),
            },
            header_storage: HeaderStorage::default(),
            pending_extensions: PendingExtensions::default(),
            extension_payload: None,
        }
    }

    /// Sets the maximum size accepted for each subsequent pax extension.
    ///
    /// A local or global pax header that declares a larger payload is rejected
    /// before any of its payload blocks are consumed. Setting the maximum to
    /// [`u64::MAX`] removes the per-extension bound; global extensions remain
    /// subject to their cumulative limit.
    ///
    /// See [`TarStream::set_max_pax_extension_size`].
    pub fn set_max_pax_extension_size(&mut self, max_pax_extension_size: u64) {
        self.payload
            .stream
            .set_max_pax_extension_size(max_pax_extension_size);
    }

    /// Sets the maximum cumulative size of global pax extensions before one member.
    ///
    /// A global header that would increase the pending total beyond this limit
    /// is rejected before its payload is consumed. Setting the maximum to
    /// [`u64::MAX`] removes the cumulative bound; each extension remains
    /// subject to its individual limit.
    ///
    /// See [`TarStream::set_max_global_pax_extensions_size`].
    pub fn set_max_global_pax_extensions_size(&mut self, max_global_pax_extensions_size: u64) {
        self.payload
            .stream
            .set_max_global_pax_extensions_size(max_global_pax_extensions_size);
    }

    /// Sets whether wholly NUL numeric metadata fields may be accepted.
    ///
    /// See [`TarStream::set_allow_all_nul_numeric_fields`].
    pub fn set_allow_all_nul_numeric_fields(&mut self, allow: bool) {
        self.payload.stream.set_allow_all_nul_numeric_fields(allow);
    }

    /// Sets the maximum size accepted for each subsequent GNU metadata extension.
    ///
    /// A long-name or long-link header that declares a larger payload is
    /// rejected before any of its payload blocks are consumed. Setting the
    /// maximum to [`u64::MAX`] permits unbounded metadata buffering.
    pub fn set_max_gnu_extension_size(&mut self, max_gnu_extension_size: u64) {
        self.payload
            .stream
            .set_max_gnu_extension_size(max_gnu_extension_size);
    }
}

impl<R: AsyncRead + Unpin> TarReader<R> {
    /// Returns the next ordinary archive member.
    ///
    /// If the preceding member payload was not fully consumed, it is first
    /// drained and validated. Extension metadata is then consumed and attached
    /// before the next member is returned. Global pax updates not followed by
    /// an ordinary member are consumed and ignored. A returned pax state is a
    /// view borrowing this reader; it must be dropped before requesting another
    /// member.
    pub async fn next_frame(&mut self) -> Result<Option<MemberFrame<'_, R>>, FrameError> {
        if let Err(error) = self.payload.drain_payload().await {
            self.clear_extension_state();
            return Err(error);
        }

        loop {
            let frame = match self.payload.stream.next_frame().await {
                Ok(Some(frame)) => frame,
                Err(error) => {
                    self.clear_extension_state();
                    return Err(error);
                }
                Ok(None) => {
                    self.clear_extension_state();
                    return Ok(None);
                }
            };
            match frame {
                Frame::Pax(frame) => {
                    self.extension_payload = Some(ExtensionPayload::Pax {
                        position: frame.position,
                        kind: frame.kind,
                    });
                }
                Frame::Gnu(frame) => {
                    if frame.payload_size == 0 {
                        let metadata = GnuMetadata {
                            position: frame.position,
                            payload: Vec::new(),
                        };
                        self.pending_extensions.set_gnu(frame.kind, metadata);
                    } else {
                        self.extension_payload = Some(ExtensionPayload::Gnu {
                            position: frame.position,
                            kind: frame.kind,
                            remaining: frame.payload_size,
                            payload: Vec::new(),
                        });
                    }
                }
                Frame::Header(header) => {
                    let pending_extensions = mem::take(&mut self.pending_extensions);
                    let extensions = match header.format {
                        ArchiveFormat::Pax => MemberExtensions::Pax(PaxState::new(
                            self.global_pax_records.as_ref(),
                            pending_extensions.global_pax,
                            pending_extensions.local_pax,
                        )),
                        ArchiveFormat::Gnu => MemberExtensions::Gnu {
                            long_name: pending_extensions.gnu_long_name,
                            long_link: pending_extensions.gnu_long_link,
                        },
                    };
                    self.payload.remaining = header.effective_size;
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
                    if let Err(error) = self.process_extension_data(frame) {
                        self.clear_extension_state();
                        return Err(error);
                    }
                }
            }
        }
    }

    fn clear_extension_state(&mut self) {
        self.pending_extensions = PendingExtensions::default();
        self.extension_payload = None;
    }

    fn process_extension_data(&mut self, frame: DataFrame) -> Result<(), FrameError> {
        let Some(payload) = self.extension_payload.take() else {
            return Err(FrameError::unexpected_order(
                frame.position,
                "extension header or ordinary member header",
                "unattached payload data",
            ));
        };
        match payload {
            ExtensionPayload::Pax { position, kind } => {
                if frame.owner != DataOwner::Pax(kind) {
                    return Err(FrameError::unexpected_order(
                        frame.position,
                        "pax extension payload",
                        "different payload data",
                    ));
                }
                if let Some(records) = frame.into_completed_pax_records() {
                    match kind {
                        PaxKind::Global => {
                            records.apply_global(&mut self.global_pax_records);
                            self.pending_extensions
                                .global_pax
                                .push(PaxExtension::new(position, kind, records));
                        }
                        PaxKind::Local => {
                            self.pending_extensions.local_pax =
                                Some(PaxExtension::new(position, kind, records));
                        }
                    }
                } else {
                    self.extension_payload = Some(ExtensionPayload::Pax { position, kind });
                }
            }
            ExtensionPayload::Gnu {
                position,
                kind,
                mut remaining,
                mut payload,
            } => {
                if frame.owner != DataOwner::Gnu(kind) {
                    return Err(FrameError::unexpected_order(
                        frame.position,
                        "GNU metadata payload",
                        "different payload data",
                    ));
                }
                let len = u64::try_from(frame.len).map_err(|_| {
                    FrameError::arithmetic_overflow(frame.position, "GNU metadata payload length")
                })?;
                remaining = remaining.checked_sub(len).ok_or_else(|| {
                    FrameError::unexpected_order(
                        frame.position,
                        "bounded GNU metadata payload",
                        "oversized GNU metadata payload",
                    )
                })?;
                payload.extend_from_slice(&frame.block[..frame.len]);
                if remaining == 0 {
                    let metadata = GnuMetadata { position, payload };
                    self.pending_extensions.set_gnu(kind, metadata);
                } else {
                    self.extension_payload = Some(ExtensionPayload::Gnu {
                        position,
                        kind,
                        remaining,
                        payload,
                    });
                }
            }
        }
        Ok(())
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
            return Ok(false);
        }
        let len = self.stream.read_member_chunk(buffer, target_len).await?;
        let len = u64::try_from(len).map_err(|_| {
            FrameError::arithmetic_overflow(self.stream.position, "member payload chunk length")
        })?;
        self.remaining = self.remaining.checked_sub(len).ok_or_else(|| {
            FrameError::unexpected_order(
                self.stream.position,
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
    /// When this returns `true`, the buffer's existing contents are replaced.
    /// When the payload is exhausted, it returns `false` without changing the
    /// buffer so its initialized storage can be reused. Complete physical blocks
    /// are read directly into it until the chunk contains at least `target_len`
    /// bytes or the payload ends. The target is raised to one physical block
    /// when it is smaller, and final-block padding is removed before this
    /// returns. This preserves [`Self::next_block`] as the lossless interface
    /// while allowing higher-level consumers to amortize per-block bookkeeping
    /// and copies.
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

fn effective_member_path<'a>(
    header: &Header<'a>,
    extensions: &'a MemberExtensions<'_>,
) -> Result<Cow<'a, [u8]>, FrameError> {
    match extensions {
        MemberExtensions::Pax(state) => resolve_pax_text(
            header.position,
            state,
            &PaxKeyword::Path,
            "path",
            Cow::Borrowed(header.header_path),
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
            None => Ok(Cow::Borrowed(header.header_path)),
        },
    }
}

fn reject_nul(position: u64, field: &'static str, value: &[u8]) -> Result<(), FrameError> {
    if value.contains(&0) {
        return Err(FrameError::at(
            position,
            FrameErrorInner::NulInMemberName { field },
        ));
    }
    Ok(())
}

fn resolve_pax_text<'a>(
    position: u64,
    state: &'a PaxState<'_>,
    keyword: &PaxKeyword,
    field: &'static str,
    header_value: Cow<'a, [u8]>,
    select: fn(&PaxRecord) -> Option<&PaxValue<PaxString>>,
) -> Result<Cow<'a, [u8]>, FrameError> {
    if let Some(value) = state.effective_record(keyword).and_then(select) {
        return pax_value(position, field, value);
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
        PaxValue::Value(PaxString::Binary(value)) => Ok(Cow::Borrowed(value.as_ref())),
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
        BLOCK_SIZE, DEFAULT_MAX_GNU_EXTENSION_SIZE, FrameError, FrameErrorInner, PaxRecord,
        PaxValue,
        header::{
            GID_RANGE, GNAME_RANGE, LINK_NAME_RANGE, MODE_RANGE, MTIME_RANGE, NAME_RANGE,
            PREFIX_RANGE, TYPEFLAG_OFFSET, UID_RANGE, UNAME_RANGE,
        },
        stream::DataOwner,
        test_support::{
            ChunkedReader, append_block, append_gnu, append_pax, append_payload, append_terminator,
            cancel_pending, gnu_header, header, ready, ready_ok, record, set_checksum,
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

    fn pax_state<'a, R>(member: &'a MemberFrame<'_, R>) -> Option<&'a PaxState<'a>> {
        if let MemberExtensions::Pax(state) = &member.extensions {
            Some(state)
        } else {
            None
        }
    }

    fn member_followed_by_empty_member(payload: &[u8]) -> (Vec<u8>, u64) {
        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'0', payload);
        let next_position = u64::try_from(bytes.len()).expect("test position should fit u64");
        append_block(&mut bytes, &header(b'0', 0));
        append_terminator(&mut bytes);
        (bytes, next_position)
    }

    #[test]
    fn exposes_ordinary_header_metadata_and_decodes_modes() {
        let mut ustar_header = header(b'2', 0);
        set_field(&mut ustar_header, NAME_RANGE, b"file");
        set_field(&mut ustar_header, PREFIX_RANGE, b"dir");
        set_field(&mut ustar_header, LINK_NAME_RANGE, b"target");
        ustar_header[MODE_RANGE].copy_from_slice(b"0100644\0");
        ustar_header[UID_RANGE].copy_from_slice(b"0000001\0");
        ustar_header[GID_RANGE].copy_from_slice(b"0000002\0");
        ustar_header[MTIME_RANGE].copy_from_slice(b"00000000003\0");
        set_field(&mut ustar_header, UNAME_RANGE, b"user");
        set_field(&mut ustar_header, GNAME_RANGE, b"group");
        set_checksum(&mut ustar_header);

        let mut empty_header = header(b'0', 0);
        for range in [
            MODE_RANGE,
            UID_RANGE,
            GID_RANGE,
            MTIME_RANGE,
            UNAME_RANGE,
            GNAME_RANGE,
        ] {
            empty_header[range].fill(0);
        }
        set_checksum(&mut empty_header);

        ready_ok(async {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &ustar_header);
            append_block(&mut bytes, &empty_header);
            append_terminator(&mut bytes);
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            {
                let member = next_member(&mut reader).await?;
                assert_eq!(member.header.format, ArchiveFormat::Pax);
                assert_eq!(member.header.header_path, b"dir/file");
                assert_eq!(member.header.link_name, b"target");
                assert_eq!(member.header.mode, Some(0o100644));
                assert_eq!(member.header.uid, Some(1));
                assert_eq!(member.header.gid, Some(2));
                assert_eq!(member.header.mtime, Some(3));
                assert_eq!(member.header.uname, b"user");
                assert_eq!(member.header.gname, b"group");
                assert_eq!(member.effective_path()?.as_ref(), b"dir/file");
                assert_eq!(member.effective_link_path()?.as_ref(), b"target");
            }
            let member = next_member(&mut reader).await?;
            assert_eq!(member.header.mode, None);
            assert_eq!(member.header.uid, None);
            assert_eq!(member.header.gid, None);
            assert_eq!(member.header.mtime, None);
            assert!(member.header.uname.is_empty());
            assert!(member.header.gname.is_empty());
            Ok(())
        });

        let mut gnu_member_header = gnu_header(b'0', 0);
        set_field(&mut gnu_member_header, NAME_RANGE, b"name");
        set_field(&mut gnu_member_header, PREFIX_RANGE, b"ignored");
        gnu_member_header[MODE_RANGE].fill(0);
        gnu_member_header[MODE_RANGE.start] = 0x80;
        gnu_member_header[MODE_RANGE.end - 2..MODE_RANGE.end].copy_from_slice(&[0x81, 0xa4]);
        set_checksum(&mut gnu_member_header);

        let mut empty_gnu_header = gnu_header(b'0', 0);
        for range in [MODE_RANGE, UID_RANGE, GID_RANGE, MTIME_RANGE] {
            empty_gnu_header[range].fill(0);
        }
        set_checksum(&mut empty_gnu_header);

        ready_ok(async {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &gnu_member_header);
            append_block(&mut bytes, &empty_gnu_header);
            append_terminator(&mut bytes);
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            {
                let member = next_member(&mut reader).await?;
                assert_eq!(member.header.format, ArchiveFormat::Gnu);
                assert_eq!(member.header.header_path, b"name");
                assert_eq!(member.header.mode, Some(0o100644));
                assert_eq!(member.header.uid, Some(0));
                assert_eq!(member.header.gid, Some(0));
                assert_eq!(member.header.mtime, Some(0));
            }
            let member = next_member(&mut reader).await?;
            assert_eq!(member.header.mode, None);
            assert_eq!(member.header.uid, None);
            assert_eq!(member.header.gid, None);
            assert_eq!(member.header.mtime, None);
            Ok(())
        });
    }

    #[test]
    fn preserves_ustar_separator_when_name_is_empty() {
        let mut ustar_header = header(b'5', 0);
        set_field(&mut ustar_header, NAME_RANGE, b"");
        set_field(&mut ustar_header, PREFIX_RANGE, b"victim");
        set_checksum(&mut ustar_header);

        ready_ok(async {
            let mut bytes = Vec::new();
            append_block(&mut bytes, &ustar_header);
            append_terminator(&mut bytes);
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let member = next_member(&mut reader).await?;
            assert_eq!(member.header.header_path, b"victim/");
            assert_eq!(member.effective_path()?.as_ref(), b"victim/");
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
            assert_eq!(member.header.header_path, b"dir/file");
            assert_eq!(member.header.link_name, b"target");
            assert_eq!(member.header.mode, Some(0o755));
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
        append_pax(&mut bytes, b'g', &global);
        append_pax(&mut bytes, b'x', &local);
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
    fn rejects_empty_effective_member_paths() {
        for (case, mut bytes) in [
            ("pax-header", {
                let mut bytes = Vec::new();
                let mut member = header(b'0', 0);
                set_field(&mut member, NAME_RANGE, b"");
                set_field(&mut member, PREFIX_RANGE, b"");
                set_checksum(&mut member);
                append_block(&mut bytes, &member);
                bytes
            }),
            ("gnu-header", {
                let mut bytes = Vec::new();
                let mut member = gnu_header(b'0', 0);
                set_field(&mut member, NAME_RANGE, b"");
                set_checksum(&mut member);
                append_block(&mut bytes, &member);
                bytes
            }),
            ("gnu-long-name", {
                let mut bytes = Vec::new();
                append_gnu(&mut bytes, b'L', b"\0");
                let mut member = gnu_header(b'0', 0);
                set_field(&mut member, NAME_RANGE, b"physical");
                set_checksum(&mut member);
                append_block(&mut bytes, &member);
                bytes
            }),
        ] {
            append_terminator(&mut bytes);
            let result: Result<(), FrameError> = ready(async {
                let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
                let member = next_member(&mut reader).await?;
                member.effective_path().map(|_| ())
            });
            assert!(
                matches!(
                    result,
                    Err(FrameError {
                        inner: FrameErrorInner::EmptyMemberPath,
                        ..
                    })
                ),
                "{case}: {result:?}"
            );
        }
    }

    #[test]
    fn rejects_nul_in_effective_member_names() {
        for (field, mut bytes) in [
            ("path", {
                let mut bytes = Vec::new();
                append_pax(&mut bytes, b'x', &record("path", "bad\0name"));
                append_block(&mut bytes, &header(b'0', 0));
                bytes
            }),
            ("link path", {
                let mut bytes = Vec::new();
                append_pax(&mut bytes, b'x', &record("linkpath", "bad\0target"));
                append_block(&mut bytes, &header(b'2', 0));
                bytes
            }),
        ] {
            append_terminator(&mut bytes);
            let result: Result<(), FrameError> = ready(async {
                let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
                let member = next_member(&mut reader).await?;
                if field == "path" {
                    member.effective_path().map(|_| ())
                } else {
                    member.effective_link_path().map(|_| ())
                }
            });
            assert!(
                matches!(
                    result,
                    Err(FrameError {
                        inner: FrameErrorInner::NulInMemberName { field: found },
                        ..
                    }) if found == field
                ),
                "{field}: {result:?}"
            );
        }
    }

    #[test]
    fn ignores_nul_in_overridden_pax_member_names() {
        let mut global = record("path", "bad\0name");
        global.extend_from_slice(&record("linkpath", "bad\0target"));
        let mut local = record("path", "good-name");
        local.extend_from_slice(&record("linkpath", "good-target"));
        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'g', &global);
        append_pax(&mut bytes, b'x', &local);
        append_block(&mut bytes, &header(b'2', 0));
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            let member = next_member(&mut reader).await?;
            assert_eq!(member.effective_path()?.as_ref(), b"good-name");
            assert_eq!(member.effective_link_path()?.as_ref(), b"good-target");
            Ok(())
        });
    }

    #[test]
    fn accepts_nonempty_extension_paths_over_empty_header_names() {
        for (case, mut bytes, expected) in [
            (
                "pax",
                {
                    let mut bytes = Vec::new();
                    append_pax(&mut bytes, b'x', &record("path", "pax-name"));
                    let mut member = header(b'0', 0);
                    set_field(&mut member, NAME_RANGE, b"");
                    set_field(&mut member, PREFIX_RANGE, b"");
                    set_checksum(&mut member);
                    append_block(&mut bytes, &member);
                    bytes
                },
                b"pax-name".as_slice(),
            ),
            (
                "gnu",
                {
                    let mut bytes = Vec::new();
                    append_gnu(&mut bytes, b'L', b"gnu-name\0");
                    let mut member = gnu_header(b'0', 0);
                    set_field(&mut member, NAME_RANGE, b"");
                    set_checksum(&mut member);
                    append_block(&mut bytes, &member);
                    bytes
                },
                b"gnu-name".as_slice(),
            ),
        ] {
            append_terminator(&mut bytes);
            ready_ok(async {
                let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
                let member = next_member(&mut reader).await?;
                assert_eq!(member.effective_path()?.as_ref(), expected, "{case}");
                Ok(())
            });
        }
    }

    #[test]
    fn global_path_deletion_suppresses_the_physical_header_path() {
        let mut physical_header = header(b'0', 0);
        set_field(&mut physical_header, NAME_RANGE, b"physical");
        set_checksum(&mut physical_header);

        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'g', &record("path", "global"));
        append_block(&mut bytes, &header(b'0', 0));
        append_pax(&mut bytes, b'g', &record("path", ""));
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
                state.effective_record(&PaxKeyword::Path),
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
    fn groups_pax_metadata_and_streams_member_payload() {
        let mut global = record("comment", "first");
        global.extend_from_slice(&record("comment", "last"));
        let mut local = record("path", "renamed");
        local.extend_from_slice(&record("size", "513"));
        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'g', &global);
        append_pax(&mut bytes, b'x', &local);
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
                    [
                        PaxRecord::Comment(PaxValue::Value("first".into())),
                        PaxRecord::Comment(PaxValue::Value("last".into())),
                    ]
                );
                assert_eq!(extensions[1].position, (BLOCK_SIZE * 2) as u64);
                assert_eq!(extensions[1].kind, PaxKind::Local);
                assert_eq!(
                    state.effective_record(&PaxKeyword::Size),
                    Some(&PaxRecord::Size(PaxValue::Value(513)))
                );
                assert_eq!(
                    state.effective_record(&PaxKeyword::Comment),
                    Some(&PaxRecord::Comment(PaxValue::Value("last".into())))
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
    fn bounds_cumulative_global_pax_extension_payloads() {
        let payload = record("comment", "metadata");
        let payload_size = u64::try_from(payload.len()).expect("payload size should fit u64");
        let limit = payload_size
            .checked_mul(2)
            .expect("test payload total should fit u64");

        let mut rejected = Vec::new();
        append_pax(&mut rejected, b'g', &payload);
        append_pax(&mut rejected, b'g', &payload);
        let rejected_position =
            u64::try_from(rejected.len()).expect("test position should fit u64");
        append_block(&mut rejected, &header(b'g', payload_size));
        let error: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(rejected, BLOCK_SIZE));
            reader.set_max_global_pax_extensions_size(limit);
            reader.next_frame().await.map(|_| ())
        });
        assert!(matches!(
            error,
            Err(FrameError {
                position,
                inner: FrameErrorInner::GlobalPaxExtensionsTooLarge {
                    size,
                    limit: found_limit,
                },
            }) if position == rejected_position
                && size == payload_size * 3
                && found_limit == limit
        ));

        let mut accepted = Vec::new();
        for _ in 0..2 {
            for _ in 0..3 {
                append_pax(&mut accepted, b'g', &payload);
            }
            append_block(&mut accepted, &header(b'0', 0));
        }
        append_terminator(&mut accepted);
        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(accepted, BLOCK_SIZE));
            reader.set_max_global_pax_extensions_size(payload_size * 3);
            for _ in 0..2 {
                let member = next_member(&mut reader).await?;
                assert_eq!(
                    pax_state(&member)
                        .expect("expected pax member metadata")
                        .extensions()
                        .count(),
                    3
                );
            }
            Ok(())
        });
    }

    #[test]
    fn retains_global_pax_extension_across_cancelled_reads() {
        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'g', &record("comment", "metadata"));
        let after_extension_header = BLOCK_SIZE;
        let after_extension_payload = bytes.len();
        append_block(&mut bytes, &header(b'0', 0));
        append_terminator(&mut bytes);

        for pending_at in [after_extension_header, after_extension_payload] {
            let mut reader = TarReader::new(ChunkedReader::pending_once(bytes.clone(), pending_at));
            cancel_pending(reader.next_frame());

            ready_ok(async {
                let member = next_member(&mut reader).await?;
                let state = pax_state(&member).expect("expected pax member metadata");
                let extensions = state.extensions().collect::<Vec<_>>();
                assert_eq!(extensions.len(), 1);
                assert_eq!(extensions[0].position, 0);
                assert_eq!(extensions[0].kind, PaxKind::Global);
                assert_eq!(
                    extensions[0].records(),
                    &[PaxRecord::Comment(PaxValue::Value("metadata".into()))]
                );
                Ok(())
            });
        }
    }

    #[test]
    fn retains_gnu_metadata_across_cancelled_reads() {
        let expected_name = vec![b'n'; BLOCK_SIZE + 10];
        let mut long_name = expected_name.clone();
        long_name.push(0);

        let mut bytes = Vec::new();
        append_gnu(&mut bytes, b'L', &long_name);
        let after_first_payload_block = BLOCK_SIZE * 2;
        append_block(&mut bytes, &gnu_header(b'0', 0));
        append_terminator(&mut bytes);

        let mut reader = TarReader::new(ChunkedReader::pending_once(
            bytes,
            after_first_payload_block,
        ));
        cancel_pending(reader.next_frame());

        ready_ok(async {
            let member = next_member(&mut reader).await?;
            assert_eq!(member.effective_path()?.as_ref(), expected_name);
            Ok(())
        });

        let mut bytes = Vec::new();
        append_gnu(&mut bytes, b'L', &[]);
        let after_extension_header = bytes.len();
        append_block(&mut bytes, &gnu_header(b'0', 0));
        append_terminator(&mut bytes);
        let mut reader = TarReader::new(ChunkedReader::pending_once(bytes, after_extension_header));
        cancel_pending(reader.next_frame());

        ready_ok(async {
            let member = next_member(&mut reader).await?;
            assert!(matches!(
                &member.extensions,
                MemberExtensions::Gnu {
                    long_name: Some(GnuMetadata { payload, .. }),
                    ..
                } if payload.is_empty()
            ));
            Ok(())
        });
    }

    #[test]
    fn applies_global_pax_updates_to_each_borrowed_state() {
        let first = record("comment", "first");
        let second = record("gname", "second");
        let replacement = record("comment", "replacement");
        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'g', &first);
        append_pax(&mut bytes, b'g', &second);
        append_block(&mut bytes, &header(b'0', 0));
        append_block(&mut bytes, &header(b'0', 0));
        append_pax(&mut bytes, b'g', &replacement);
        append_block(&mut bytes, &header(b'0', 0));
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            {
                let member = next_member(&mut reader).await?;
                let state = pax_state(&member).expect("expected pax member metadata");
                let extensions = state.extensions().collect::<Vec<_>>();
                assert_eq!(extensions.len(), 2);
                assert_eq!(extensions[0].position, 0);
                assert_eq!(extensions[1].position, (BLOCK_SIZE * 2) as u64);
                assert_eq!(
                    state.effective_record(&PaxKeyword::Comment),
                    Some(&PaxRecord::Comment(PaxValue::Value("first".into())))
                );
            }
            {
                let member = next_member(&mut reader).await?;
                let state = pax_state(&member).expect("expected pax member metadata");
                assert_eq!(state.extensions().count(), 0);
                assert_eq!(
                    state.effective_record(&PaxKeyword::Comment),
                    Some(&PaxRecord::Comment(PaxValue::Value("first".into())))
                );
            }

            let member = next_member(&mut reader).await?;
            let state = pax_state(&member).expect("expected pax member metadata");
            let extensions = state.extensions().collect::<Vec<_>>();
            assert_eq!(extensions.len(), 1);
            assert_eq!(extensions[0].kind, PaxKind::Global);
            assert_eq!(
                state.effective_record(&PaxKeyword::Comment),
                Some(&PaxRecord::Comment(PaxValue::Value("replacement".into())))
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
        append_pax(&mut bytes, b'0', &payload);
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
            let allocation = chunk.as_ptr();
            assert_eq!(chunk, payload[..BLOCK_SIZE * 2]);
            assert!(
                member
                    .payload
                    .next_chunk(&mut chunk, BLOCK_SIZE + 1)
                    .await?
            );
            assert_eq!(chunk.as_ptr(), allocation);
            assert_eq!(chunk, payload[BLOCK_SIZE * 2..]);
            assert!(
                !member
                    .payload
                    .next_chunk(&mut chunk, BLOCK_SIZE + 1)
                    .await?
            );
            assert_eq!(chunk, payload[BLOCK_SIZE * 2..]);
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });
    }

    #[test]
    fn resumes_cancelled_member_payload_chunk_with_either_read_api() {
        let payload = (0..BLOCK_SIZE * 2 + 17)
            .map(|index| u8::try_from(index % 251).expect("test byte should fit"))
            .collect::<Vec<_>>();
        let (bytes, next_member_position) = member_followed_by_empty_member(&payload);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::pending_once(bytes, BLOCK_SIZE + 73));
            {
                let mut member = next_member(&mut reader).await?;
                let mut cancelled_buffer = vec![b'x'; 17];
                cancel_pending(
                    member
                        .payload
                        .next_chunk(&mut cancelled_buffer, payload.len()),
                );
                assert!(cancelled_buffer.is_empty());

                let first = member
                    .payload
                    .next_block()
                    .await?
                    .expect("cancelled chunk should resume as a payload block");
                let mut resumed_buffer = vec![b'y'; 23];
                assert!(member.payload.next_chunk(&mut resumed_buffer, 1).await?);
                let mut observed = first.block[..first.len].to_vec();
                observed.extend_from_slice(&resumed_buffer);
                assert_eq!(observed, payload);
                assert!(!member.payload.next_chunk(&mut resumed_buffer, 1).await?);
            }

            let member = next_member(&mut reader).await?;
            assert_eq!(member.header.position, next_member_position);
            Ok(())
        });
    }

    #[test]
    fn resumes_cancelled_member_payload_block_during_automatic_drain() {
        let payload = vec![b'x'; BLOCK_SIZE * 2 + 17];
        let (bytes, next_member_position) = member_followed_by_empty_member(&payload);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::pending_once(bytes, BLOCK_SIZE + 73));
            {
                let mut member = next_member(&mut reader).await?;
                cancel_pending(member.payload.next_block());
            }

            let member = next_member(&mut reader).await?;
            assert_eq!(member.header.position, next_member_position);
            drop(member);
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });
    }

    #[test]
    fn resumes_cancelled_automatic_payload_drain() {
        let payload = vec![b'x'; BLOCK_SIZE * 2 + 17];
        let (bytes, next_member_position) = member_followed_by_empty_member(&payload);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::pending_once(bytes, BLOCK_SIZE + 73));
            drop(next_member(&mut reader).await?);
            cancel_pending(reader.next_frame());

            let member = next_member(&mut reader).await?;
            assert_eq!(member.header.position, next_member_position);
            drop(member);
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });
    }

    #[test]
    fn reports_cancelled_chunk_errors_at_physical_block_boundaries() {
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
                let mut reader =
                    TarReader::new(ChunkedReader::pending_once(bytes, BLOCK_SIZE + 73));
                let Ok(Some(mut member)) = reader.next_frame().await else {
                    panic!("expected member");
                };
                let mut buffer = Vec::new();
                cancel_pending(member.payload.next_chunk(&mut buffer, BLOCK_SIZE * 2));
                member.payload.next_chunk(&mut buffer, BLOCK_SIZE * 2).await
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
    fn rejects_oversized_gnu_extensions_before_consuming_payload() {
        let declared_size = 9;
        for (case, typeflag) in [("long-name", b'L'), ("long-link", b'K')] {
            let mut reader = TarReader::new(ChunkedReader::new(
                gnu_header(typeflag, declared_size).to_vec(),
                BLOCK_SIZE,
            ));
            reader.set_max_gnu_extension_size(declared_size - 1);
            assert!(
                matches!(
                    ready(reader.next_frame()),
                    Err(FrameError {
                        position: 0,
                        inner: FrameErrorInner::ExtensionTooLarge {
                            format: ArchiveFormat::Gnu,
                            size,
                            limit,
                        },
                    }) if size == declared_size && limit == declared_size - 1
                ),
                "{case}"
            );
        }

        let mut reader = TarReader::new(ChunkedReader::new(
            gnu_header(b'L', DEFAULT_MAX_GNU_EXTENSION_SIZE + 1).to_vec(),
            BLOCK_SIZE,
        ));
        assert!(matches!(
            ready(reader.next_frame()),
            Err(FrameError {
                position: 0,
                inner: FrameErrorInner::ExtensionTooLarge {
                    format: ArchiveFormat::Gnu,
                    size,
                    limit: DEFAULT_MAX_GNU_EXTENSION_SIZE,
                },
            }) if size == DEFAULT_MAX_GNU_EXTENSION_SIZE + 1
        ));
    }

    #[test]
    fn logical_reader_is_fused_after_oversized_gnu_extension() {
        let payload = b"renamed\0";
        let payload_size = u64::try_from(payload.len()).expect("payload size should fit u64");
        let mut bytes = Vec::new();
        append_gnu(&mut bytes, b'L', payload);
        append_block(&mut bytes, &gnu_header(b'0', 0));
        append_terminator(&mut bytes);

        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
            reader.set_max_gnu_extension_size(payload_size - 1);
            assert!(matches!(
                reader.next_frame().await,
                Err(FrameError {
                    position: 0,
                    inner: FrameErrorInner::ExtensionTooLarge {
                        format: ArchiveFormat::Gnu,
                        size,
                        limit,
                    },
                }) if size == payload_size && limit == payload_size - 1
            ));
            assert!(reader.next_frame().await?.is_none());
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
        append_pax(&mut global, b'g', &record("comment", "metadata"));
        append_pax(&mut global, b'g', &record("gname", "group"));
        append_terminator(&mut global);
        ready_ok(async {
            let mut reader = TarReader::new(ChunkedReader::new(global, BLOCK_SIZE));
            assert!(reader.next_frame().await?.is_none());
            Ok(())
        });

        let mut malformed_global = Vec::new();
        append_pax(&mut malformed_global, b'g', b"invalid");
        append_terminator(&mut malformed_global);
        let error: Result<(), FrameError> = ready(async {
            let mut reader = TarReader::new(ChunkedReader::new(malformed_global, BLOCK_SIZE));
            reader.next_frame().await.map(|_| ())
        });
        assert!(matches!(
            error,
            Err(FrameError {
                position: 0,
                inner: FrameErrorInner::InvalidPaxRecord { .. },
            })
        ));
    }

    #[test]
    fn skips_unread_payload_before_advancing() {
        for payload_len in [BLOCK_SIZE + 1, PAYLOAD_DRAIN_CHUNK_BYTES + 7] {
            let payload = vec![b'a'; payload_len];
            let mut bytes = Vec::new();
            append_pax(&mut bytes, b'0', &payload);
            append_block(&mut bytes, &header(b'0', 0));
            append_terminator(&mut bytes);

            ready_ok(async {
                let mut reader = TarReader::new(ChunkedReader::new(bytes, BLOCK_SIZE));
                {
                    let member = next_member(&mut reader).await?;
                    member.payload.skip().await?;
                }
                let member = next_member(&mut reader).await?;
                assert_eq!(member.header.effective_size, 0);
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
