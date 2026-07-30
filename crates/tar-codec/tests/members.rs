pub mod support;

use std::{
    cell::Cell,
    error::Error,
    io,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use support::{ArchiveBuilder, ArchiveFormat, header, pax_record, set_checksum};
use tar_codec::{
    Archive as _, DecodeError, DecodePolicy, DecodePolicyViolation, Member, MemberPayload,
    PaxDecodePolicy, SpecialKind, TarArchive,
};
use tar_framing::{
    FrameError, FrameErrorInner, GnuKind, PaxKeyword,
    header::{GID_RANGE, MODE_RANGE, MTIME_RANGE, UID_RANGE},
};
use tokio::io::{AsyncRead, ReadBuf};

type TestResult = Result<(), Box<dyn Error>>;

struct CountingReader<'a> {
    bytes: &'a [u8],
    position: usize,
    reads: Rc<Cell<usize>>,
}

impl AsyncRead for CountingReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = buffer
            .remaining()
            .min(self.bytes.len().saturating_sub(self.position));
        let end = self.position + len;
        buffer.put_slice(&self.bytes[self.position..end]);
        self.position = end;
        self.reads.set(self.reads.get() + 1);
        Poll::Ready(Ok(()))
    }
}

async fn read_payload<P: MemberPayload<Error = DecodeError>>(
    mut payload: P,
) -> Result<Vec<u8>, DecodeError> {
    let mut data = Vec::new();
    let mut chunk = Vec::new();
    while payload.next_chunk(&mut chunk, 3).await? {
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

#[tokio::test]
async fn buffers_member_reads_by_default_and_allows_unbuffered_sources() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("first", b'0', b"first payload", "", 0o644)
        .ustar("second", b'0', b"second payload", "", 0o644);
    let bytes = archive.finish();

    for buffered in [true, false] {
        let reads = Rc::new(Cell::new(0));
        let reader = CountingReader {
            bytes: bytes.as_slice(),
            position: 0,
            reads: Rc::clone(&reads),
        };
        let archive = if buffered {
            TarArchive::new(reader)
        } else {
            TarArchive::unbuffered(reader)
        };
        let mut members = archive.members();

        for expected in [b"first payload".as_slice(), b"second payload".as_slice()] {
            let Some(Member::File { payload, .. }) = members.next().await? else {
                return Err(io::Error::other("expected regular file member").into());
            };
            assert_eq!(read_payload(payload).await?, expected);
        }
        assert!(members.next().await?.is_none());
        if buffered {
            assert_eq!(reads.get(), 1);
        } else {
            assert!(reads.get() > 1);
        }
    }

    let mut archive = ArchiveBuilder::new();
    archive.gnu("file", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::unbuffered_with_policy(
        bytes.as_slice(),
        DecodePolicy::default().allow_gnu(false),
    )
    .members();
    assert!(matches!(
        members.next().await,
        Err(DecodeError::PolicyViolation { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn projects_every_member_kind_and_streams_payloads() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("file", b'0', b"contents", "", 0o755)
        .ustar("contiguous", b'7', b"contiguous", "", 0o644)
        .ustar("directory", b'5', b"", "", 0o755)
        .ustar("symbolic", b'2', b"", "file", 0o777)
        .ustar("hard", b'1', b"replacement", "file", 0o644)
        .ustar("character", b'3', b"", "", 0o644)
        .ustar("block", b'4', b"", "", 0o644)
        .ustar("fifo", b'6', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();

    let Some(Member::File {
        metadata,
        size,
        executable,
        payload,
    }) = members.next().await?
    else {
        return Err(io::Error::other("expected regular file member").into());
    };
    assert_eq!(metadata.path, "file");
    assert_eq!(metadata.position, 0);
    assert_eq!(size, 8);
    assert!(executable);
    assert_eq!(read_payload(payload).await?, b"contents");

    let Some(Member::File {
        metadata, payload, ..
    }) = members.next().await?
    else {
        return Err(io::Error::other("expected contiguous file member").into());
    };
    assert_eq!(metadata.path, "contiguous");
    assert_eq!(read_payload(payload).await?, b"contiguous");

    assert!(matches!(
        members.next().await?,
        Some(Member::Directory { metadata }) if metadata.path == "directory"
    ));
    assert!(matches!(
        members.next().await?,
        Some(Member::SymbolicLink {
            metadata,
            target,
        }) if metadata.path == "symbolic" && target == "file"
    ));

    let Some(Member::HardLink {
        metadata,
        target,
        size,
        payload,
    }) = members.next().await?
    else {
        return Err(io::Error::other("expected hard-link member").into());
    };
    assert_eq!(metadata.path, "hard");
    assert_eq!(target, "file");
    assert_eq!(size, 11);
    assert_eq!(read_payload(payload).await?, b"replacement");

    for (path, kind) in [
        ("character", SpecialKind::CharacterDevice),
        ("block", SpecialKind::BlockDevice),
        ("fifo", SpecialKind::Fifo),
    ] {
        assert!(matches!(
            members.next().await?,
            Some(Member::Special {
                metadata,
                kind: actual,
            }) if metadata.path == path && actual == kind
        ));
    }
    assert!(members.next().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn all_nul_numeric_fields_are_policy_controlled() -> TestResult {
    let strict_policy = DecodePolicy::default().allow_all_nul_numeric_fields(false);

    for format in [ArchiveFormat::Pax, ArchiveFormat::Gnu] {
        for (field, range) in [
            ("mode", MODE_RANGE),
            ("uid", UID_RANGE),
            ("gid", GID_RANGE),
            ("mtime", MTIME_RANGE),
        ] {
            let path = format!("empty-{format:?}-{field}");
            let mut block = header(format, &path, b'0', 0, "", 0o644);
            block[range].fill(0);
            set_checksum(&mut block);

            let mut archive = ArchiveBuilder::new();
            archive.block(&block);
            let bytes = archive.finish();
            {
                let mut members = TarArchive::new(bytes.as_slice()).members();
                assert!(matches!(
                    members.next().await?,
                    Some(Member::File {
                        metadata,
                        executable: false,
                        ..
                    }) if metadata.path == path
                ));
                assert!(members.next().await?.is_none());
            }

            let mut members = TarArchive::new(bytes.as_slice())
                .with_policy(strict_policy.clone())
                .members();
            assert!(
                matches!(members.next().await, Err(DecodeError::Framing(_))),
                "strict policy should reject an all-NUL {format:?} {field} field"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn resolves_format_metadata_but_leaves_extraction_paths_raw() -> TestResult {
    let records = [
        pax_record(PaxKeyword::Path, "../effective"),
        pax_record(PaxKeyword::LinkPath, "../target"),
    ]
    .concat();
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &records)
        .ustar("raw", b'2', b"", "ignored", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();
    assert!(matches!(
        members.next().await?,
        Some(Member::SymbolicLink { metadata, target })
            if metadata.path == "../effective" && target == "../target"
    ));

    let mut archive = ArchiveBuilder::new();
    archive
        .gnu("longname", b'L', b"effective\0", "", 0o644)
        .gnu("longlink", b'K', b"target\0", "", 0o644)
        .gnu("raw", b'2', b"", "ignored", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();
    assert!(matches!(
        members.next().await?,
        Some(Member::SymbolicLink { metadata, target })
            if metadata.path == "effective" && target == "target"
    ));
    Ok(())
}

#[tokio::test]
async fn advancing_drains_payload_and_applies_tar_policy() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("first", b'0', &[b'a'; 1024], "", 0o644)
        .ustar("second", b'0', b"next", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();
    {
        let Some(Member::File { mut payload, .. }) = members.next().await? else {
            return Err(io::Error::other("expected first file member").into());
        };
        let mut chunk = Vec::new();
        assert!(payload.next_chunk(&mut chunk, 1).await?);
    }
    let Some(Member::File { payload, .. }) = members.next().await? else {
        return Err(io::Error::other("expected second file member").into());
    };
    assert_eq!(read_payload(payload).await?, b"next");

    let mut archive = ArchiveBuilder::new();
    archive.ustar("truncated", b'0', &[b'x'; 1024], "", 0o644);
    let mut bytes = archive.finish();
    bytes.truncate(1025);
    let mut members = TarArchive::new(bytes.as_slice()).members();
    {
        let Some(Member::File { mut payload, .. }) = members.next().await? else {
            return Err(io::Error::other("expected truncated file member").into());
        };
        let mut chunk = Vec::new();
        assert!(payload.next_chunk(&mut chunk, 1).await?);
    }
    assert!(matches!(members.next().await, Err(DecodeError::Framing(_))));

    let mut archive = ArchiveBuilder::new();
    archive.gnu("file", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice())
        .with_policy(DecodePolicy::default().allow_gnu(false))
        .members();
    assert!(matches!(
        members.next().await,
        Err(DecodeError::PolicyViolation { .. })
    ));

    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &pax_record(PaxKeyword::Comment, "metadata"))
        .ustar("file", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice())
        .with_policy(
            DecodePolicy::default().pax_policy(PaxDecodePolicy::default().max_extension_size(1)),
        )
        .members();
    assert!(matches!(members.next().await, Err(DecodeError::Framing(_))));
    Ok(())
}

#[tokio::test]
async fn payload_chunk_preflight_errors_fuse_member_iteration() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &pax_record(PaxKeyword::Size, &u64::MAX.to_string()))
        .ustar("oversized", b'0', b"", "", 0o644);
    let bytes = archive.into_unterminated();
    let mut members = TarArchive::new(bytes.as_slice()).members();
    let Some(Member::File { mut payload, .. }) = members.next().await? else {
        return Err(io::Error::other("expected oversized file member").into());
    };

    let mut chunk = Vec::new();
    assert!(matches!(
        payload.next_chunk(&mut chunk, usize::MAX).await,
        Err(DecodeError::Framing(FrameError {
            inner: FrameErrorInner::ArithmeticOverflow {
                context: "member payload chunk physical length",
            },
            ..
        }))
    ));

    for attempt in 1..=2 {
        assert!(
            matches!(members.next().await, Ok(None)),
            "iteration {attempt}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn payload_errors_fuse_member_iteration() -> TestResult {
    #[derive(Clone, Copy, Debug)]
    enum Operation {
        Read,
        Skip,
    }

    let bytes = header(ArchiveFormat::Pax, "truncated", b'0', 5, "", 0o644);

    for operation in [Operation::Read, Operation::Skip] {
        let mut members = TarArchive::new(bytes.as_slice()).members();
        let Some(Member::File { mut payload, .. }) = members.next().await? else {
            return Err(io::Error::other("expected truncated file member").into());
        };

        let result = match operation {
            Operation::Read => {
                let mut chunk = Vec::new();
                payload.next_chunk(&mut chunk, 1).await.map(|_| ())
            }
            Operation::Skip => payload.skip().await,
        };
        assert!(
            matches!(result, Err(DecodeError::Framing(_))),
            "{operation:?}"
        );

        for attempt in 1..=2 {
            assert!(
                matches!(members.next().await, Ok(None)),
                "{operation:?}, iteration {attempt}"
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn projection_errors_fuse_member_iteration() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .gnu("longname", b'L', b"no-nul", "", 0o644)
        .gnu("first", b'0', b"", "", 0o644)
        .gnu("second", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();

    assert!(matches!(
        members.next().await,
        Err(DecodeError::Framing(FrameError {
            inner: FrameErrorInner::InvalidGnuMetadata {
                kind: GnuKind::LongName,
                ..
            },
            ..
        }))
    ));
    assert!(members.next().await?.is_none());

    Ok(())
}

#[tokio::test]
async fn policy_errors_fuse_member_iteration() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &pax_record(PaxKeyword::Path, "forbidden"))
        .ustar("first", b'0', b"", "", 0o644)
        .ustar("second", b'0', b"payload", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();

    assert!(matches!(
        members.next().await,
        Err(DecodeError::PolicyViolation {
            violation: DecodePolicyViolation::GlobalPaxMemberMetadata { keyword: "path" },
            ..
        })
    ));
    assert!(members.next().await?.is_none());
    Ok(())
}
