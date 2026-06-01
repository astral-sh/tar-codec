//! Strict POSIX-pax block construction.
//!
//! This module builds deterministic pax framing blocks without performing I/O.
//! Higher-level crates remain responsible for writing payload bytes and for
//! deciding which filesystem entries are appropriate to archive.

use crate::{
    BLOCK_SIZE, Block, MemberKind,
    header::{
        CHECKSUM_RANGE, GID_RANGE, IDENTITY_RANGE, LINK_NAME_RANGE, MODE_RANGE, MTIME_RANGE,
        NAME_RANGE, POSIX_IDENTITY, PREFIX_RANGE, SIZE_RANGE, TYPEFLAG_OFFSET, UID_RANGE,
        encode_checksum_value, encode_octal,
    },
};

const MAX_DECIMAL_U64_BYTES: usize = 20;
const MAX_SEQUENCE_NAME_BYTES: usize = b"PaxHeaders/".len() + MAX_DECIMAL_U64_BYTES;

/// Metadata needed to frame one supported pax archive member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaxMember<'a> {
    /// The UTF-8 member path written into the local pax header.
    pub path: &'a str,
    /// The supported ordinary member kind.
    pub kind: MemberKind,
    /// The meaningful regular-file payload size.
    pub size: u64,
    /// The UTF-8 symbolic-link target, when `kind` is [`MemberKind::SymbolicLink`].
    pub link_path: Option<&'a str>,
    /// Whether a regular file should carry executable intent.
    pub executable: bool,
}

/// Deterministic framing blocks for one pax archive member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaxMemberBlocks {
    /// The local pax `x` header block.
    pub extended_header: Block,
    /// The padded local pax payload blocks.
    pub extended_payload: Vec<Block>,
    /// The ordinary POSIX-ustar member header block.
    pub member_header: Block,
}

/// A failure while constructing strict pax framing blocks.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FramingWriteError {
    /// The requested ordinary member kind is outside the encoder subset.
    #[error("cannot encode unsupported member type {kind:?}")]
    UnsupportedMemberKind {
        /// The rejected ordinary member kind.
        kind: MemberKind,
    },
    /// A member kind that cannot carry data was assigned a nonzero payload size.
    #[error("member type {kind:?} cannot carry payload size {size}")]
    InvalidMemberSize {
        /// The affected member kind.
        kind: MemberKind,
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
        kind: MemberKind,
    },
    /// A required text value is empty or contains a NUL byte.
    #[error("invalid pax {field}: values must be non-empty and cannot contain NUL bytes")]
    InvalidText {
        /// The affected metadata field.
        field: &'static str,
    },
    /// The local pax extended header payload cannot fit its ustar size field.
    #[error("pax extended header payload is too large: {size} bytes")]
    ExtendedHeaderTooLarge {
        /// The unpadded local pax payload size.
        size: u64,
    },
    /// An internal length or checksum computation exceeded its framing range.
    #[error("arithmetic overflow while constructing {context}")]
    ArithmeticOverflow {
        /// The failed framing computation.
        context: &'static str,
    },
}

/// Builds one local pax header and its following ordinary member header.
///
/// The local extended header always carries `path` and `size`. Symbolic links
/// additionally carry `linkpath`. The ordinary member header contains
/// deterministic POSIX-ustar fallback values for readers that ignore pax.
pub fn frame_pax_member(
    sequence: u64,
    member: PaxMember<'_>,
) -> Result<PaxMemberBlocks, FramingWriteError> {
    let mut bytes = Vec::new();
    frame_pax_member_into(sequence, member, &mut bytes)?;
    let member_header_start =
        bytes
            .len()
            .checked_sub(BLOCK_SIZE)
            .ok_or(FramingWriteError::ArithmeticOverflow {
                context: "pax framing block length",
            })?;
    let extended_header = block_from_slice(bytes.get(..BLOCK_SIZE).ok_or(
        FramingWriteError::ArithmeticOverflow {
            context: "pax framing block length",
        },
    )?)?;
    let extended_payload = bytes
        .get(BLOCK_SIZE..member_header_start)
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax framing block length",
        })?
        .chunks_exact(BLOCK_SIZE)
        .map(block_from_slice)
        .collect::<Result<Vec<_>, _>>()?;
    let member_header = block_from_slice(bytes.get(member_header_start..).ok_or(
        FramingWriteError::ArithmeticOverflow {
            context: "pax framing block length",
        },
    )?)?;

    Ok(PaxMemberBlocks {
        extended_header,
        extended_payload,
        member_header,
    })
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
    let path_record_len = record_len("path", member.path.as_bytes())?;
    let size_record_len = record_len("size", size)?;
    let link_path_record_len = member
        .link_path
        .map(|link_path| record_len("linkpath", link_path.as_bytes()))
        .transpose()?;
    let payload_len = path_record_len
        .checked_add(size_record_len)
        .and_then(|len| {
            link_path_record_len.map_or(Some(len), |link_len| len.checked_add(link_len))
        })
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax payload length",
        })?;
    let payload_size =
        u64::try_from(payload_len).map_err(|_| FramingWriteError::ArithmeticOverflow {
            context: "pax payload length",
        })?;
    let padded_payload_len = padded_payload_len(payload_len)?;

    let mut extended_name_buffer = [0; MAX_SEQUENCE_NAME_BYTES];
    let extended_name = prefixed_decimal_name(b"PaxHeaders/", sequence, &mut extended_name_buffer)?;
    let extended_header = build_header(extended_name, 0o644, payload_size, b'x', b"")?;

    let mut fallback_name_buffer = [0; MAX_SEQUENCE_NAME_BYTES];
    let fallback_name = prefixed_decimal_name(b"PaxEntries/", sequence, &mut fallback_name_buffer)?;
    let member_name = if split_ustar_path(member.path.as_bytes()).is_some() {
        member.path.as_bytes()
    } else {
        fallback_name
    };
    let fallback_size = if fits_octal(SIZE_RANGE.len(), member.size) {
        member.size
    } else {
        0
    };
    let (mode, typeflag) = match member.kind {
        MemberKind::Regular => (if member.executable { 0o755 } else { 0o644 }, b'0'),
        MemberKind::Directory => (0o755, b'5'),
        MemberKind::SymbolicLink => (0o777, b'2'),
        _ => {
            return Err(FramingWriteError::UnsupportedMemberKind { kind: member.kind });
        }
    };
    let member_header = build_header(
        member_name,
        mode,
        fallback_size,
        typeflag,
        member.link_path.unwrap_or_default().as_bytes(),
    )?;

    let framing_len = BLOCK_SIZE
        .checked_add(padded_payload_len)
        .and_then(|len| len.checked_add(BLOCK_SIZE))
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax framing length",
        })?;
    buffer.clear();
    buffer.reserve(framing_len);
    buffer.extend_from_slice(&extended_header);
    append_record_with_len(buffer, "path", member.path.as_bytes(), path_record_len);
    append_record_with_len(buffer, "size", size, size_record_len);
    if let Some(link_path) = member.link_path
        && let Some(record_len) = link_path_record_len
    {
        append_record_with_len(buffer, "linkpath", link_path.as_bytes(), record_len);
    }
    buffer.resize(BLOCK_SIZE + padded_payload_len, 0);
    buffer.extend_from_slice(&member_header);
    Ok(())
}

/// Returns the required two-block POSIX end-of-archive marker.
pub fn end_marker() -> [Block; 2] {
    [[0; BLOCK_SIZE], [0; BLOCK_SIZE]]
}

fn validate_member(member: PaxMember<'_>) -> Result<(), FramingWriteError> {
    validate_text("path", member.path)?;
    match member.kind {
        MemberKind::Regular | MemberKind::Directory => {
            if member.link_path.is_some() {
                return Err(FramingWriteError::UnexpectedLinkPath { kind: member.kind });
            }
            if member.kind == MemberKind::Directory && member.size != 0 {
                return Err(FramingWriteError::InvalidMemberSize {
                    kind: member.kind,
                    size: member.size,
                });
            }
        }
        MemberKind::SymbolicLink => {
            if member.size != 0 {
                return Err(FramingWriteError::InvalidMemberSize {
                    kind: member.kind,
                    size: member.size,
                });
            }
            let Some(link_path) = member.link_path else {
                return Err(FramingWriteError::MissingLinkPath);
            };
            validate_text("linkpath", link_path)?;
        }
        _ => {
            return Err(FramingWriteError::UnsupportedMemberKind { kind: member.kind });
        }
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), FramingWriteError> {
    if value.is_empty() || value.contains('\0') {
        return Err(FramingWriteError::InvalidText { field });
    }
    Ok(())
}

fn record_len(keyword: &'static str, value: &[u8]) -> Result<usize, FramingWriteError> {
    let suffix_len = 1_usize
        .checked_add(keyword.len())
        .and_then(|len| len.checked_add(1))
        .and_then(|len| len.checked_add(value.len()))
        .and_then(|len| len.checked_add(1))
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax record length",
        })?;
    let mut len = suffix_len
        .checked_add(1)
        .ok_or(FramingWriteError::ArithmeticOverflow {
            context: "pax record length",
        })?;
    loop {
        let actual = decimal_len(len).checked_add(suffix_len).ok_or(
            FramingWriteError::ArithmeticOverflow {
                context: "pax record length",
            },
        )?;
        if actual == len {
            return Ok(len);
        }
        len = actual;
    }
}

fn append_record_with_len(payload: &mut Vec<u8>, keyword: &'static str, value: &[u8], len: usize) {
    append_decimal_usize(payload, len);
    payload.push(b' ');
    payload.extend_from_slice(keyword.as_bytes());
    payload.push(b'=');
    payload.extend_from_slice(value);
    payload.push(b'\n');
}

fn build_header(
    path: &[u8],
    mode: u64,
    size: u64,
    typeflag: u8,
    link_path: &[u8],
) -> Result<Block, FramingWriteError> {
    let mut block = [0; BLOCK_SIZE];
    let (prefix, name) = split_ustar_path(path).ok_or(FramingWriteError::ArithmeticOverflow {
        context: "ustar fallback path",
    })?;
    block[NAME_RANGE.start..NAME_RANGE.start + name.len()].copy_from_slice(name);
    block[PREFIX_RANGE.start..PREFIX_RANGE.start + prefix.len()].copy_from_slice(prefix);
    let encoded_link_path = if link_path.len() <= LINK_NAME_RANGE.len() {
        block[LINK_NAME_RANGE.start..LINK_NAME_RANGE.start + link_path.len()]
            .copy_from_slice(link_path);
        link_path
    } else {
        &[]
    };
    if !encode_octal(&mut block[MODE_RANGE], mode)
        || !encode_octal(&mut block[UID_RANGE], 0)
        || !encode_octal(&mut block[GID_RANGE], 0)
        || !encode_octal(&mut block[SIZE_RANGE], size)
        || !encode_octal(&mut block[MTIME_RANGE], 0)
    {
        return Err(FramingWriteError::ExtendedHeaderTooLarge { size });
    }
    block[TYPEFLAG_OFFSET] = typeflag;
    block[IDENTITY_RANGE].copy_from_slice(POSIX_IDENTITY);
    let checksum = byte_sum(name)
        + byte_sum(prefix)
        + byte_sum(encoded_link_path)
        + byte_sum(&block[MODE_RANGE])
        + byte_sum(&block[UID_RANGE])
        + byte_sum(&block[GID_RANGE])
        + byte_sum(&block[SIZE_RANGE])
        + byte_sum(&block[MTIME_RANGE])
        + u64::from(typeflag)
        + byte_sum(POSIX_IDENTITY)
        + CHECKSUM_RANGE.len() as u64 * u64::from(b' ');
    if !encode_checksum_value(&mut block, checksum) {
        return Err(FramingWriteError::ArithmeticOverflow {
            context: "ustar checksum",
        });
    }
    Ok(block)
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
    let remainder = len % BLOCK_SIZE;
    if remainder == 0 {
        Ok(len)
    } else {
        len.checked_add(BLOCK_SIZE - remainder)
            .ok_or(FramingWriteError::ArithmeticOverflow {
                context: "padded pax payload length",
            })
    }
}

fn prefixed_decimal_name<'a>(
    prefix: &[u8],
    value: u64,
    buffer: &'a mut [u8],
) -> Result<&'a [u8], FramingWriteError> {
    let mut digits_buffer = [0; MAX_DECIMAL_U64_BYTES];
    let digits = decimal_u64(value, &mut digits_buffer);
    let len =
        prefix
            .len()
            .checked_add(digits.len())
            .ok_or(FramingWriteError::ArithmeticOverflow {
                context: "pax fallback name length",
            })?;
    let Some(name) = buffer.get_mut(..len) else {
        return Err(FramingWriteError::ArithmeticOverflow {
            context: "pax fallback name length",
        });
    };
    name[..prefix.len()].copy_from_slice(prefix);
    name[prefix.len()..].copy_from_slice(digits);
    Ok(name)
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

fn decimal_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 10 {
        value /= 10;
        len += 1;
    }
    len
}

fn append_decimal_usize(output: &mut Vec<u8>, mut value: usize) {
    let mut buffer = [0; std::mem::size_of::<usize>() * 3];
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            output.extend_from_slice(&buffer[start..]);
            return;
        }
    }
}

fn block_from_slice(bytes: &[u8]) -> Result<Block, FramingWriteError> {
    bytes
        .try_into()
        .map_err(|_| FramingWriteError::ArithmeticOverflow {
            context: "pax framing block length",
        })
}

fn byte_sum(bytes: &[u8]) -> u64 {
    bytes.iter().map(|byte| u64::from(*byte)).sum()
}

#[cfg(test)]
mod tests {
    use tokio_stream::StreamExt;

    use super::*;
    use crate::{
        PaxKind, PaxRecord, PaxString, PaxValue,
        header::parse_octal,
        stream::{Frame, TarStream},
        test_support::{ChunkedReader, ready},
    };

    fn flatten(blocks: PaxMemberBlocks, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&blocks.extended_header);
        for block in blocks.extended_payload {
            bytes.extend_from_slice(&block);
        }
        bytes.extend_from_slice(&blocks.member_header);
        for chunk in payload.chunks(BLOCK_SIZE) {
            let mut block = [0; BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            bytes.extend_from_slice(&block);
        }
        for block in end_marker() {
            bytes.extend_from_slice(&block);
        }
        bytes
    }

    #[test]
    fn frames_regular_directory_and_symbolic_link_members() {
        let members = [
            PaxMember {
                path: "bin/tool",
                kind: MemberKind::Regular,
                size: 3,
                link_path: None,
                executable: true,
            },
            PaxMember {
                path: "bin",
                kind: MemberKind::Directory,
                size: 0,
                link_path: None,
                executable: false,
            },
            PaxMember {
                path: "alias",
                kind: MemberKind::SymbolicLink,
                size: 0,
                link_path: Some("bin/tool"),
                executable: false,
            },
        ];
        for (sequence, member) in members.into_iter().enumerate() {
            let payload: &[u8] = if member.kind == MemberKind::Regular {
                b"run"
            } else {
                b""
            };
            let bytes = flatten(
                frame_pax_member(sequence as u64, member).expect("valid member"),
                payload,
            );
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
            assert!(
                header
                    .local_pax_records
                    .contains(&PaxRecord::Path(PaxValue::Value(PaxString::Utf8(
                        member.path.to_owned()
                    ))))
            );
        }
    }

    #[test]
    fn frames_members_into_a_reusable_buffer() {
        let member = PaxMember {
            path: "bin/tool",
            kind: MemberKind::Regular,
            size: 3,
            link_path: None,
            executable: true,
        };
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
        for block in end_marker() {
            bytes.extend_from_slice(&block);
        }
        let frames = ready(TarStream::new(ChunkedReader::new(bytes, 19)).collect::<Vec<_>>());
        assert!(frames.iter().all(Result::is_ok));
    }

    #[test]
    fn uses_generated_fallbacks_for_long_paths_and_links() {
        let path = format!("{}/{}", "a".repeat(156), "b".repeat(101));
        let link_path = "c".repeat(101);
        let blocks = frame_pax_member(
            7,
            PaxMember {
                path: &path,
                kind: MemberKind::SymbolicLink,
                size: 0,
                link_path: Some(&link_path),
                executable: false,
            },
        )
        .expect("valid member");
        assert_eq!(
            &blocks.member_header[NAME_RANGE.start..NAME_RANGE.start + 12],
            b"PaxEntries/7"
        );
        assert!(
            blocks.member_header[LINK_NAME_RANGE]
                .iter()
                .all(|byte| *byte == 0)
        );

        let bytes = flatten(blocks, b"");
        let frames = ready(TarStream::new(ChunkedReader::new(bytes, 23)).collect::<Vec<_>>());
        let header = frames
            .iter()
            .find_map(|frame| match frame {
                Ok(Frame::Header(header)) => Some(header),
                _ => None,
            })
            .expect("member header");
        assert_eq!(header.local_pax_records.len(), 3);
    }

    #[test]
    fn rejects_unsupported_or_inconsistent_members() {
        let member = PaxMember {
            path: "file",
            kind: MemberKind::HardLink,
            size: 0,
            link_path: None,
            executable: false,
        };
        assert_eq!(
            frame_pax_member(0, member),
            Err(FramingWriteError::UnsupportedMemberKind {
                kind: MemberKind::HardLink
            })
        );
        assert!(matches!(
            frame_pax_member(
                0,
                PaxMember {
                    path: "link",
                    kind: MemberKind::SymbolicLink,
                    size: 1,
                    link_path: Some("file"),
                    executable: false,
                }
            ),
            Err(FramingWriteError::InvalidMemberSize { .. })
        ));
    }

    #[test]
    fn uses_zero_ustar_fallback_for_oversized_regular_payloads() {
        let blocks = frame_pax_member(
            0,
            PaxMember {
                path: "large",
                kind: MemberKind::Regular,
                size: u64::MAX,
                link_path: None,
                executable: false,
            },
        )
        .expect("pax size can represent u64 values");
        assert_eq!(parse_octal(&blocks.member_header[SIZE_RANGE]), Some(0));
    }
}
