//! Strict POSIX-pax block construction.
//!
//! This module builds deterministic pax framing blocks without performing I/O.
//! Higher-level crates remain responsible for writing payload bytes and for
//! deciding which filesystem entries are appropriate to archive.

use crate::{
    BLOCK_SIZE, Block, MemberKind,
    header::{
        GID_RANGE, IDENTITY_RANGE, LINK_NAME_RANGE, MODE_RANGE, MTIME_RANGE, NAME_RANGE,
        POSIX_IDENTITY, PREFIX_RANGE, SIZE_RANGE, TYPEFLAG_OFFSET, UID_RANGE, encode_checksum,
        encode_octal,
    },
};

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
    validate_member(member)?;

    let mut payload = Vec::new();
    append_record(&mut payload, "path", member.path.as_bytes())?;
    append_record(&mut payload, "size", member.size.to_string().as_bytes())?;
    if let Some(link_path) = member.link_path {
        append_record(&mut payload, "linkpath", link_path.as_bytes())?;
    }
    let payload_size =
        u64::try_from(payload.len()).map_err(|_| FramingWriteError::ArithmeticOverflow {
            context: "pax payload length",
        })?;

    let extended_name = format!("PaxHeaders/{sequence}");
    let extended_header = build_header(&extended_name, 0o644, payload_size, b'x', "")?;

    let fallback_name = format!("PaxEntries/{sequence}");
    let member_name = if split_ustar_path(member.path).is_some() {
        member.path
    } else {
        &fallback_name
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
        member.link_path.unwrap_or_default(),
    )?;

    Ok(PaxMemberBlocks {
        extended_header,
        extended_payload: payload_blocks(&payload),
        member_header,
    })
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

fn append_record(
    payload: &mut Vec<u8>,
    keyword: &'static str,
    value: &[u8],
) -> Result<(), FramingWriteError> {
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
        let prefix = len.to_string();
        let actual =
            prefix
                .len()
                .checked_add(suffix_len)
                .ok_or(FramingWriteError::ArithmeticOverflow {
                    context: "pax record length",
                })?;
        if actual == len {
            payload.extend_from_slice(prefix.as_bytes());
            payload.push(b' ');
            payload.extend_from_slice(keyword.as_bytes());
            payload.push(b'=');
            payload.extend_from_slice(value);
            payload.push(b'\n');
            return Ok(());
        }
        len = actual;
    }
}

fn payload_blocks(payload: &[u8]) -> Vec<Block> {
    payload
        .chunks(BLOCK_SIZE)
        .map(|chunk| {
            let mut block = [0; BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect()
}

fn build_header(
    path: &str,
    mode: u64,
    size: u64,
    typeflag: u8,
    link_path: &str,
) -> Result<Block, FramingWriteError> {
    let mut block = [0; BLOCK_SIZE];
    let (prefix, name) = split_ustar_path(path).ok_or(FramingWriteError::ArithmeticOverflow {
        context: "ustar fallback path",
    })?;
    block[NAME_RANGE.start..NAME_RANGE.start + name.len()].copy_from_slice(name.as_bytes());
    block[PREFIX_RANGE.start..PREFIX_RANGE.start + prefix.len()].copy_from_slice(prefix.as_bytes());
    if link_path.len() <= LINK_NAME_RANGE.len() {
        block[LINK_NAME_RANGE.start..LINK_NAME_RANGE.start + link_path.len()]
            .copy_from_slice(link_path.as_bytes());
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
    block[IDENTITY_RANGE].copy_from_slice(POSIX_IDENTITY);
    if !encode_checksum(&mut block) {
        return Err(FramingWriteError::ArithmeticOverflow {
            context: "ustar checksum",
        });
    }
    Ok(block)
}

fn fits_octal(field_len: usize, value: u64) -> bool {
    value.checked_ilog(8).map_or(1, |log| log + 1) < field_len as u32
}

fn split_ustar_path(path: &str) -> Option<(&str, &str)> {
    if path.len() <= NAME_RANGE.len() {
        return Some(("", path));
    }
    path.match_indices('/').rev().find_map(|(separator, _)| {
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
