pub mod support;

use std::{error::Error, io};

use support::{ArchiveBuilder, pax_record};
use tar_codec::{
    Archive as _, DecodeError, DecodePolicy, DecodePolicyViolation, Member, MemberPayload,
    PaxDecodePolicy, SpecialKind, TarArchive,
};
use tar_framing::PaxKeyword;

type TestResult = Result<(), Box<dyn Error>>;

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
async fn projects_every_member_kind_and_streams_payloads() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("file", b'0', b"contents", "", 0o755)
        .posix("contiguous", b'7', b"contiguous", "", 0o644)
        .posix("directory", b'5', b"", "", 0o755)
        .posix("symbolic", b'2', b"", "file", 0o777)
        .posix("hard", b'1', b"replacement", "file", 0o644)
        .posix("character", b'3', b"", "", 0o644)
        .posix("block", b'4', b"", "", 0o644)
        .posix("fifo", b'6', b"", "", 0o644);
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
async fn resolves_format_metadata_but_leaves_extraction_paths_raw() -> TestResult {
    let records = [
        pax_record(PaxKeyword::Path, "../effective"),
        pax_record(PaxKeyword::LinkPath, "../target"),
    ]
    .concat();
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &records)
        .posix("raw", b'2', b"", "ignored", 0o644);
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
        .posix("first", b'0', &[b'a'; 1024], "", 0o644)
        .posix("second", b'0', b"next", "", 0o644);
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
    archive.posix("truncated", b'0', &[b'x'; 1024], "", 0o644);
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
    let mut members =
        TarArchive::new_with_policy(bytes.as_slice(), DecodePolicy::default().allow_gnu(false))
            .members();
    assert!(matches!(
        members.next().await,
        Err(DecodeError::PolicyViolation { .. })
    ));

    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &pax_record(PaxKeyword::Comment, "metadata"))
        .posix("file", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new_with_policy(
        bytes.as_slice(),
        DecodePolicy::default().pax_policy(PaxDecodePolicy::default().max_extension_size(1)),
    )
    .members();
    assert!(matches!(members.next().await, Err(DecodeError::Framing(_))));
    Ok(())
}

#[tokio::test]
async fn policy_errors_fuse_member_iteration() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &pax_record(PaxKeyword::Path, "forbidden"))
        .posix("first", b'0', b"", "", 0o644)
        .posix("second", b'0', b"payload", "", 0o644);
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
