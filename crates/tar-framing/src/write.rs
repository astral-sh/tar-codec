//! Strict POSIX-pax block construction.
//!
//! This module builds deterministic pax framing blocks without performing I/O.
//! Higher-level crates remain responsible for writing payload bytes and for
//! deciding which filesystem entries are appropriate to archive.

use crate::{
    BLOCK_SIZE, Block, PaxKeyword, UstarKind,
    header::{
        GID_RANGE, IDENTITY_RANGE, LINK_NAME_RANGE, MODE_RANGE, MTIME_RANGE, NAME_RANGE,
        PREFIX_RANGE, SIZE_RANGE, TYPEFLAG_OFFSET, UID_RANGE, USTAR_IDENTITY, encode_checksum,
        encode_octal,
    },
};

const MAX_DECIMAL_U64_BYTES: usize = 20;
const MAX_SEQUENCE_NAME_BYTES: usize = b"PaxHeaders/".len() + MAX_DECIMAL_U64_BYTES;
const ZERO_BLOCK: Block = [0; BLOCK_SIZE];
const END_MARKER_BYTES: [u8; BLOCK_SIZE * 2] = [0; BLOCK_SIZE * 2];

/// Metadata needed to frame one supported pax archive member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaxMember<'a> {
    /// The UTF-8 member path written into the local pax header.
    ///
    /// Non-directory paths cannot end in `/` or a final `.` or `..` component.
    pub path: &'a str,
    /// The supported ordinary member kind.
    pub kind: UstarKind,
    /// The meaningful regular-file payload size.
    pub size: u64,
    /// The UTF-8 symbolic-link target, when `kind` is [`UstarKind::SymbolicLink`].
    pub link_path: Option<&'a str>,
    /// Whether a regular file should carry executable intent.
    pub executable: bool,
}

/// A failure while constructing strict pax framing blocks.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FramingWriteError {
    /// The requested ordinary member kind is outside the encoder subset.
    #[error("cannot encode unsupported member type {kind:?}")]
    UnsupportedMemberKind {
        /// The rejected ordinary member kind.
        kind: UstarKind,
    },
    /// A member kind that cannot carry data was assigned a nonzero payload size.
    #[error("member type {kind:?} cannot carry payload size {size}")]
    InvalidMemberSize {
        /// The affected member kind.
        kind: UstarKind,
        /// The rejected payload size.
        size: u64,
    },
    /// A symbolic link was missing its required target.
    #[error("symbolic-link member is missing its link path")]
    MissingLinkPath,
    /// A non-symbolic-link member unexpectedly supplied a link target.
    #[error("member type {kind:?} cannot carry a link path")]
    UnexpectedLinkPath {
        /// The affected member kind.
        kind: UstarKind,
    },
    /// A required text value is empty or contains a NUL byte.
    #[error("invalid pax {field}: values must be non-empty and cannot contain NUL bytes")]
    InvalidText {
        /// The affected metadata field.
        field: &'static str,
    },
    /// A PAX record keyword is empty or contains `=`.
    #[error("pax record keywords must be non-empty and cannot contain '='")]
    InvalidPaxRecordKeyword,
    /// A non-directory member path has a suffix that requires a directory.
    #[error("member type {kind:?} cannot have a directory-required path suffix")]
    DirectoryRequiredPathSuffix {
        /// The affected member kind.
        kind: UstarKind,
    },
    /// The local pax extended header payload cannot fit its ustar size field.
    #[error("pax extended header payload is too large: {size} bytes")]
    ExtendedHeaderTooLarge {
        /// The unpadded local pax payload size.
        size: u64,
    },
    /// An internal length computation exceeded its framing range.
    #[error("arithmetic overflow while constructing {context}")]
    ArithmeticOverflow {
        /// The failed framing computation.
        context: &'static str,
    },
}

/// Appends one PAX extended-header record without block padding to `output`.
///
/// `keyword` must be nonempty and cannot contain `=`. `value` is copied
/// verbatim and may contain arbitrary bytes.
pub fn append_pax_record(
    output: &mut Vec<u8>,
    keyword: &PaxKeyword,
    value: &[u8],
) -> Result<(), FramingWriteError> {
    let (namespace, name) = keyword.components();
    if namespace.is_empty()
        || namespace.contains('=')
        || name.is_some_and(|name| name.is_empty() || name.contains('='))
    {
        return Err(FramingWriteError::InvalidPaxRecordKeyword);
    }
    let len = record_len(keyword, value)?;
    output
        .len()
        .checked_add(len)
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax record output length",
        })?;
    output.reserve(len);
    append_record_with_len(output, keyword, value, len);
    Ok(())
}

/// Writes one local pax header and its ordinary member header into `buffer`.
///
/// The buffer is cleared first and its allocation is reused when possible.
/// The resulting bytes contain the local extended header block, its padded
/// records, and the ordinary POSIX-ustar member header block. Member payload
/// bytes and padding remain the caller's responsibility.
pub fn frame_pax_member_into(
    sequence: u64,
    member: PaxMember<'_>,
    buffer: &mut Vec<u8>,
) -> Result<(), FramingWriteError> {
    validate_member(member)?;

    let mut size_buffer = [0; MAX_DECIMAL_U64_BYTES];
    let size = decimal_u64(member.size, &mut size_buffer);
    let link_path = member.link_path.map(str::as_bytes);
    buffer.clear();
    buffer.resize(BLOCK_SIZE, 0);
    append_pax_record(buffer, &PaxKeyword::Path, member.path.as_bytes())?;
    append_pax_record(buffer, &PaxKeyword::Size, size)?;
    if let Some(link_path) = link_path {
        append_pax_record(buffer, &PaxKeyword::LinkPath, link_path)?;
    }
    let payload_len = buffer.len() - BLOCK_SIZE;
    let payload_size =
        u64::try_from(payload_len).map_err(|_| FramingWriteError::ArithmeticOverflow {
            context: "pax payload length",
        })?;
    let padded_payload_len = padded_payload_len(payload_len)?;

    let mut extended_name_buffer = [0; MAX_SEQUENCE_NAME_BYTES];
    let extended_name = prefixed_decimal_name(b"PaxHeaders/", sequence, &mut extended_name_buffer);
    let mut fallback_name_buffer = [0; MAX_SEQUENCE_NAME_BYTES];
    let fallback_name = prefixed_decimal_name(b"PaxEntries/", sequence, &mut fallback_name_buffer);
    let member_path = split_ustar_path(member.path.as_bytes()).unwrap_or((&[], fallback_name));
    let fallback_size = if fits_octal(SIZE_RANGE.len(), member.size) {
        member.size
    } else {
        0
    };
    let (mode, typeflag) = match member.kind {
        UstarKind::Regular => (if member.executable { 0o755 } else { 0o644 }, b'0'),
        UstarKind::Directory => (0o755, b'5'),
        UstarKind::SymbolicLink => (0o777, b'2'),
        _ => {
            return Err(FramingWriteError::UnsupportedMemberKind { kind: member.kind });
        }
    };
    let framing_len = padded_payload_len.checked_add(BLOCK_SIZE * 2).ok_or(
        FramingWriteError::ArithmeticOverflow {
            context: "pax framing length",
        },
    )?;
    buffer.resize(framing_len, 0);
    let (extended_header, rest) = buffer.split_at_mut(BLOCK_SIZE);
    let (_, member_header) = rest.split_at_mut(padded_payload_len);
    build_header_into(
        extended_header,
        (&[], extended_name),
        0o644,
        payload_size,
        b'x',
        b"",
    )?;
    build_header_into(
        member_header,
        member_path,
        mode,
        fallback_size,
        typeflag,
        member.link_path.unwrap_or_default().as_bytes(),
    )?;
    Ok(())
}

/// Returns the required two-block POSIX end-of-archive marker as contiguous bytes.
pub fn end_marker_bytes() -> &'static [u8] {
    &END_MARKER_BYTES
}

/// Returns the zero padding required after a payload of `size` meaningful bytes.
pub fn payload_padding(size: u64) -> &'static [u8] {
    match size % BLOCK_SIZE as u64 {
        0 => &[],
        remainder => &ZERO_BLOCK[..(BLOCK_SIZE as u64 - remainder) as usize],
    }
}

fn validate_member(member: PaxMember<'_>) -> Result<(), FramingWriteError> {
    validate_text("path", member.path)?;
    // Defensive: our own decoder rejects non-directories with suffixes that
    // require directory resolution, so we should never encode one.
    // TODO: Single-source this check, maybe in name validation?
    if !matches!(member.kind, UstarKind::Directory)
        && (member.path.ends_with('/')
            || member
                .path
                .rsplit('/')
                .next()
                .is_some_and(|component| matches!(component, "." | "..")))
    {
        return Err(FramingWriteError::DirectoryRequiredPathSuffix { kind: member.kind });
    }
    match member.kind {
        UstarKind::Regular | UstarKind::Directory if member.link_path.is_some() => {
            Err(FramingWriteError::UnexpectedLinkPath { kind: member.kind })
        }
        UstarKind::Directory | UstarKind::SymbolicLink if member.size != 0 => {
            Err(FramingWriteError::InvalidMemberSize {
                kind: member.kind,
                size: member.size,
            })
        }
        UstarKind::Regular | UstarKind::Directory => Ok(()),
        UstarKind::SymbolicLink => validate_text(
            "linkpath",
            member.link_path.ok_or(FramingWriteError::MissingLinkPath)?,
        ),
        _ => Err(FramingWriteError::UnsupportedMemberKind { kind: member.kind }),
    }
}

fn validate_text(field: &'static str, value: &str) -> Result<(), FramingWriteError> {
    if value.is_empty() || value.contains('\0') {
        return Err(FramingWriteError::InvalidText { field });
    }
    Ok(())
}

fn record_len(keyword: &PaxKeyword, value: &[u8]) -> Result<usize, FramingWriteError> {
    let (namespace, name) = keyword.components();
    let keyword_len = name
        .map_or(Some(namespace.len()), |name| {
            namespace
                .len()
                .checked_add(1)
                .and_then(|len| len.checked_add(name.len()))
        })
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax record keyword length",
        })?;
    let suffix_len = keyword_len
        .checked_add(value.len())
        .and_then(|len| len.checked_add(3))
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax record length",
        })?;
    let tentative_len = (suffix_len.ilog10() as usize + 1)
        .checked_add(suffix_len)
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax record length",
        })?;
    (tentative_len.ilog10() as usize + 1)
        .checked_add(suffix_len)
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax record length",
        })
}

fn append_record_with_len(payload: &mut Vec<u8>, keyword: &PaxKeyword, value: &[u8], len: usize) {
    append_decimal_usize(payload, len);
    payload.push(b' ');
    let (namespace, name) = keyword.components();
    payload.extend_from_slice(namespace.as_bytes());
    if let Some(name) = name {
        payload.push(b'.');
        payload.extend_from_slice(name.as_bytes());
    }
    payload.push(b'=');
    payload.extend_from_slice(value);
    payload.push(b'\n');
}

fn build_header_into(
    block: &mut [u8],
    (prefix, name): (&[u8], &[u8]),
    mode: u64,
    size: u64,
    typeflag: u8,
    link_path: &[u8],
) -> Result<(), FramingWriteError> {
    let block: &mut Block =
        block
            .try_into()
            .map_err(|_| FramingWriteError::ArithmeticOverflow {
                context: "ustar header block length",
            })?;
    block[NAME_RANGE.start..NAME_RANGE.start + name.len()].copy_from_slice(name);
    block[PREFIX_RANGE.start..PREFIX_RANGE.start + prefix.len()].copy_from_slice(prefix);
    if link_path.len() <= LINK_NAME_RANGE.len() {
        block[LINK_NAME_RANGE.start..LINK_NAME_RANGE.start + link_path.len()]
            .copy_from_slice(link_path);
    }
    if !encode_octal(&mut block[MODE_RANGE], mode)
        || !encode_octal(&mut block[UID_RANGE], 0)
        || !encode_octal(&mut block[GID_RANGE], 0)
        || !encode_octal(&mut block[SIZE_RANGE], size)
        || !encode_octal(&mut block[MTIME_RANGE], 0)
    {
        return Err(FramingWriteError::ExtendedHeaderTooLarge { size });
    }
    block[TYPEFLAG_OFFSET] = typeflag;
    block[IDENTITY_RANGE].copy_from_slice(USTAR_IDENTITY);
    encode_checksum(block);
    Ok(())
}

fn fits_octal(field_len: usize, value: u64) -> bool {
    value.checked_ilog(8).map_or(1, |log| log + 1) < field_len as u32
}

fn split_ustar_path(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.len() <= NAME_RANGE.len() {
        return Some((&[], path));
    }
    path.iter()
        .enumerate()
        .rev()
        .filter(|(_, byte)| **byte == b'/')
        .find_map(|(separator, _)| {
            let prefix = &path[..separator];
            let name = &path[separator + 1..];
            if !prefix.is_empty()
                && prefix.len() <= PREFIX_RANGE.len()
                && !name.is_empty()
                && name.len() <= NAME_RANGE.len()
            {
                Some((prefix, name))
            } else {
                None
            }
        })
}

fn padded_payload_len(len: usize) -> Result<usize, FramingWriteError> {
    len.checked_next_multiple_of(BLOCK_SIZE)
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "padded pax payload length",
        })
}

fn prefixed_decimal_name<'a>(
    prefix: &[u8; b"PaxHeaders/".len()],
    value: u64,
    buffer: &'a mut [u8; MAX_SEQUENCE_NAME_BYTES],
) -> &'a [u8] {
    let mut digits_buffer = [0; MAX_DECIMAL_U64_BYTES];
    let digits = decimal_u64(value, &mut digits_buffer);
    let len = prefix.len() + digits.len();
    buffer[..prefix.len()].copy_from_slice(prefix);
    buffer[prefix.len()..len].copy_from_slice(digits);
    &buffer[..len]
}

fn decimal_u64(mut value: u64, buffer: &mut [u8; MAX_DECIMAL_U64_BYTES]) -> &[u8] {
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &buffer[start..];
        }
    }
}

fn append_decimal_usize(output: &mut Vec<u8>, value: usize) {
    let mut buffer = [0; MAX_DECIMAL_U64_BYTES];
    output.extend_from_slice(decimal_u64(value as u64, &mut buffer));
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio_stream::StreamExt;

    use super::*;
    use crate::{
        PaxKind, PaxRecord, PaxString, PaxValue,
        header::parse_octal,
        stream::{Frame, TarStream},
        test_support::{ChunkedReader, ready},
    };

    fn pax_member<'a>(
        path: &'a str,
        kind: UstarKind,
        size: u64,
        link_path: Option<&'a str>,
        executable: bool,
    ) -> PaxMember<'a> {
        PaxMember {
            path,
            kind,
            size,
            link_path,
            executable,
        }
    }

    fn frame_archive(
        sequence: u64,
        member: PaxMember<'_>,
        payload: &[u8],
    ) -> Result<Vec<u8>, FramingWriteError> {
        let mut bytes = Vec::new();
        frame_pax_member_into(sequence, member, &mut bytes)?;
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(payload_padding(member.size));
        bytes.extend_from_slice(end_marker_bytes());
        Ok(bytes)
    }

    #[test]
    fn frames_regular_directory_and_symbolic_link_members() {
        let members = [
            pax_member("bin/tool", UstarKind::Regular, 3, None, true),
            pax_member("bin", UstarKind::Directory, 0, None, false),
            pax_member("alias", UstarKind::SymbolicLink, 0, Some("bin/tool"), false),
        ];
        for (sequence, member) in members.into_iter().enumerate() {
            let payload: &[u8] = if member.kind == UstarKind::Regular {
                b"run"
            } else {
                b""
            };
            let bytes = frame_archive(sequence as u64, member, payload).expect("valid member");
            let frames = ready(TarStream::new(ChunkedReader::new(bytes, 19)).collect::<Vec<_>>());
            assert!(matches!(
                &frames[0],
                Ok(Frame::Pax(frame)) if frame.kind == PaxKind::Local
            ));
            let header = frames
                .iter()
                .find_map(|frame| match frame {
                    Ok(Frame::Header(header)) => Some(header),
                    _ => None,
                })
                .expect("member header");
            assert_eq!(header.kind, member.kind);
            assert_eq!(header.effective_size, member.size);
            let records = frames
                .iter()
                .find_map(|frame| match frame {
                    Ok(Frame::Data(data)) => data.completed_pax_records(),
                    _ => None,
                })
                .expect("local pax records");
            assert!(
                records.contains(&PaxRecord::Path(PaxValue::Value(PaxString::Utf8(
                    member.path.to_owned().into()
                ))))
            );
        }
    }

    #[test]
    fn frames_members_into_a_reusable_buffer() {
        let member = pax_member("bin/tool", UstarKind::Regular, 3, None, true);
        let mut bytes = Vec::with_capacity(BLOCK_SIZE * 3);
        bytes.extend_from_slice(b"stale bytes");
        frame_pax_member_into(7, member, &mut bytes).expect("valid member");
        assert_eq!(bytes.len(), BLOCK_SIZE * 3);
        let capacity = bytes.capacity();

        frame_pax_member_into(8, member, &mut bytes).expect("valid member");
        assert_eq!(bytes.len(), BLOCK_SIZE * 3);
        assert_eq!(bytes.capacity(), capacity);

        bytes.extend_from_slice(b"run");
        bytes.resize(bytes.len() + BLOCK_SIZE - 3, 0);
        bytes.extend_from_slice(end_marker_bytes());
        let frames = ready(TarStream::new(ChunkedReader::new(bytes, 19)).collect::<Vec<_>>());
        assert!(frames.iter().all(Result::is_ok));
    }

    #[test]
    fn returns_payload_padding_and_contiguous_end_marker_bytes() {
        for (size, expected) in [
            (0, &[] as &[u8]),
            (BLOCK_SIZE as u64, &[]),
            (1, &[0; BLOCK_SIZE - 1]),
            ((BLOCK_SIZE + 7) as u64, &[0; BLOCK_SIZE - 7]),
        ] {
            assert_eq!(payload_padding(size), expected, "{size}");
        }

        assert_eq!(end_marker_bytes().len(), BLOCK_SIZE * 2);
        assert!(end_marker_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn appends_standalone_pax_records_across_decimal_boundaries() {
        let mut record = Vec::new();
        assert_eq!(
            append_pax_record(&mut record, &PaxKeyword::Path, b"b"),
            Ok(())
        );
        assert_eq!(record, b"9 path=b\n");
        record.clear();
        assert_eq!(
            append_pax_record(&mut record, &PaxKeyword::Atime, b"x"),
            Ok(())
        );
        assert_eq!(record, b"11 atime=x\n");
        for keyword in [
            PaxKeyword::Realtime(Arc::from("")),
            PaxKeyword::Vendor {
                vendor: Arc::from("invalid=vendor"),
                name: Arc::from("attribute"),
            },
        ] {
            assert_eq!(
                append_pax_record(&mut Vec::new(), &keyword, b"value"),
                Err(FramingWriteError::InvalidPaxRecordKeyword)
            );
        }
    }

    #[test]
    fn uses_generated_fallbacks_for_long_paths_and_links() {
        let path = format!("{}/{}", "a".repeat(156), "b".repeat(101));
        let link_path = "c".repeat(101);
        let member = pax_member(&path, UstarKind::SymbolicLink, 0, Some(&link_path), false);
        let mut bytes = Vec::new();
        frame_pax_member_into(7, member, &mut bytes).expect("valid member");
        let member_header = &bytes[bytes.len() - BLOCK_SIZE..];
        assert_eq!(
            &member_header[NAME_RANGE.start..NAME_RANGE.start + 12],
            b"PaxEntries/7"
        );
        assert!(member_header[LINK_NAME_RANGE].iter().all(|byte| *byte == 0));

        bytes.extend_from_slice(end_marker_bytes());
        let frames = ready(TarStream::new(ChunkedReader::new(bytes, 23)).collect::<Vec<_>>());
        let records = frames
            .iter()
            .find_map(|frame| match frame {
                Ok(Frame::Data(data)) => data.completed_pax_records(),
                _ => None,
            })
            .expect("local pax records");
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn rejects_unsupported_or_inconsistent_members() {
        for (member, expected) in [
            (
                pax_member("file", UstarKind::HardLink, 0, None, false),
                FramingWriteError::UnsupportedMemberKind {
                    kind: UstarKind::HardLink,
                },
            ),
            (
                pax_member("link", UstarKind::SymbolicLink, 1, Some("file"), false),
                FramingWriteError::InvalidMemberSize {
                    kind: UstarKind::SymbolicLink,
                    size: 1,
                },
            ),
        ] {
            assert_eq!(
                frame_pax_member_into(0, member, &mut Vec::new()),
                Err(expected)
            );
        }
    }

    #[test]
    fn uses_zero_ustar_fallback_for_oversized_regular_payloads() {
        let mut bytes = Vec::new();
        frame_pax_member_into(
            0,
            pax_member("large", UstarKind::Regular, u64::MAX, None, false),
            &mut bytes,
        )
        .expect("pax size can represent u64 values");
        assert_eq!(
            parse_octal(&bytes[bytes.len() - BLOCK_SIZE..][SIZE_RANGE]),
            Some(0)
        );
    }
}
