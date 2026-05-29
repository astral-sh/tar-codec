//! Lossless, block-oriented tar framing.
//!
//! The physical API emits one frame for each accepted non-terminator physical
//! tar block and preserves each source block verbatim.

use crate::{ArchiveFormat, BLOCK_SIZE, GnuKind, MemberKind, PaxKind, PaxRecord, pax::PaxSize};

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
    pub block: [u8; BLOCK_SIZE],
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
    pub block: [u8; BLOCK_SIZE],
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

/// A payload physical block.
///
/// This can be "real" data for e.g. a file member, or it can be the payload of a pax
/// or GNU header.
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
pub(super) struct PendingGnu {
    pub(super) long_name: bool,
    pub(super) long_link: bool,
}

/// A strict stream of POSIX-pax or GNU frames sourced from an underlying reader.
pub struct TarStream<R> {
    pub(super) position: u64,
    pub(super) inner: R,
    pub(super) block: [u8; BLOCK_SIZE],
    pub(super) block_len: usize,
    pub(super) format: Option<ArchiveFormat>,
    pub(super) global_pax_records: Vec<PaxRecord>,
    pub(super) state: State,
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio_stream::Stream;

    use super::*;
    use crate::{
        ArchiveFormat, FrameError, FrameErrorInner, IDENTITY_RANGE, PaxValue, SIZE_RANGE,
        is_zero_block,
        test_support::{
            ChunkedReader, append_block, append_payload, append_terminator, data,
            gnu_base256_header, gnu_header, header, record, set_checksum,
        },
    };

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
}
