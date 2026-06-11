pub mod support;

use support::{
    ArchiveBuilder, ArchiveFormat, header, pax_record, raw_pax_record, set_checksum,
    set_identity_byte, single_posix_member,
};
use tar_codec::{
    decode::{Archive, DecodeError, DecodePolicy, DecodePolicyViolation, PaxDecodePolicy},
    default_name_validator,
};
use tar_framing::{FrameError, FrameErrorInner};
use tempfile::tempdir;

#[tokio::test]
async fn pax_precedence_and_validation_use_effective_names() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("precedence");
    let global = pax_record("path", "wrong");
    let local_file = pax_record("path", "actual/file");
    let mut local_link = pax_record("path", "actual/link");
    local_link.extend_from_slice(&pax_record("linkpath", "file"));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &global)
        .pax(b'x', &local_file)
        .posix("raw", b'0', b"content", "", 0o644)
        .pax(b'x', &local_link)
        .posix("raw-link", b'2', b"", "wrong-target", 0o644);
    let bytes = archive.finish();
    let policy = DecodePolicy::default().pax_policy(
        PaxDecodePolicy::default()
            .allow_global_pax_extensions(true)
            .allow_global_pax_member_metadata(true),
    );
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("actual/link")).unwrap(),
        "content"
    );
    assert!(!destination.join("wrong").exists());

    let destination = temp.path().join("effective");
    let mut local_file = pax_record("path", "actual/file");
    local_file.extend_from_slice(&pax_record("comment", "metadata"));
    let mut local_link = pax_record("path", "actual/link");
    local_link.extend_from_slice(&pax_record("linkpath", "file"));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &local_file)
        .posix("raw-file", b'0', b"content", "", 0o644)
        .pax(b'x', &local_link)
        .posix("raw-link", b'2', b"", "wrong-target", 0o644);
    let bytes = archive.finish();
    let policy = DecodePolicy::default().name_validator(Some(|name| {
        !name.contains("raw") && !name.contains("wrong")
    }));
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("actual/link")).unwrap(),
        "content"
    );

    let destination = temp.path().join("rejected");
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &pax_record("path", "blocked"))
        .posix("allowed", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let policy = DecodePolicy::default().name_validator(Some(|name| {
        default_name_validator(name) && !name.contains("blocked")
    }));
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await,
        Err(DecodeError::PolicyViolation {
            violation: DecodePolicyViolation::NameRejected {
                context: "member path",
                value,
            },
            ..
        }) if value == "blocked"
    ));
}

#[tokio::test]
async fn gnu_long_metadata_and_validation_use_effective_names() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("relative-link");
    let mut archive = ArchiveBuilder::new();
    archive
        .gnu("dir/target", b'0', b"contents", "", 0o644)
        .gnu("longname", b'L', b"dir/long/link\0", "", 0o644)
        .gnu("longlink", b'K', b"../target\0", "", 0o644)
        .gnu("raw", b'2', b"", "wrong", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("dir/long/link")).unwrap(),
        "contents"
    );

    let destination = temp.path().join("effective");
    let mut archive = ArchiveBuilder::new();
    archive
        .gnu("actual", b'0', b"contents", "", 0o644)
        .gnu("longname", b'L', b"actual-link\0", "", 0o644)
        .gnu("longlink", b'K', b"actual\0", "", 0o644)
        .gnu("raw-link", b'2', b"", "wrong-target", 0o644);
    let bytes = archive.finish();
    let policy = DecodePolicy::default().name_validator(Some(|name| {
        !name.contains("raw") && !name.contains("wrong")
    }));
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("actual-link")).unwrap(),
        "contents"
    );

    let destination = temp.path().join("rejected");
    let mut archive = ArchiveBuilder::new();
    archive
        .gnu("longname", b'L', b"blocked\0", "", 0o644)
        .gnu("allowed", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let policy = DecodePolicy::default().name_validator(Some(|name| {
        default_name_validator(name) && !name.contains("blocked")
    }));
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await,
        Err(DecodeError::PolicyViolation {
            violation: DecodePolicyViolation::NameRejected { value, .. },
            ..
        }) if value == "blocked"
    ));
}

#[tokio::test]
async fn member_and_link_name_validation_is_configurable() {
    let temp = tempdir().unwrap();
    for (case, bytes, context) in [
        (
            "member",
            single_posix_member(" rejected", b'0', b"", "", 0o644),
            "member path",
        ),
        (
            "symlink",
            single_posix_member("link", b'2', b"", " rejected", 0o644),
            "symbolic-link target",
        ),
        (
            "hard-link",
            single_posix_member("link", b'1', b"", " rejected", 0o644),
            "hard-link target",
        ),
    ] {
        let policy = DecodePolicy::default().allow_hard_links(true);
        assert!(matches!(
            Archive::new(bytes.as_slice())
                .extract(temp.path().join(case), policy)
                .await,
            Err(DecodeError::PolicyViolation {
                violation: DecodePolicyViolation::NameRejected {
                    context: actual,
                    ..
                },
                ..
            }) if actual == context
        ));
    }

    let destination = temp.path().join("disabled");
    let bytes = single_posix_member(" allowed", b'0', b"ok", "", 0o644);
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default().name_validator(None))
        .await
        .unwrap();
    assert_eq!(std::fs::read(destination.join(" allowed")).unwrap(), b"ok");
}

#[tokio::test]
async fn gnu_archives_can_be_forbidden_without_rejecting_empty_archives() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("gnu");
    let mut archive = ArchiveBuilder::new();
    archive
        .gnu("longname", b'L', b"renamed\0", "", 0o644)
        .gnu("raw", b'0', b"contents", "", 0o644);
    let bytes = archive.finish();
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, DecodePolicy::default().allow_gnu(false))
            .await,
        Err(DecodeError::PolicyViolation {
            position: 0,
            violation: DecodePolicyViolation::GnuArchive,
        })
    ));
    assert!(!destination.join("renamed").exists());

    let bytes = ArchiveBuilder::new().finish();
    Archive::new(bytes.as_slice())
        .extract(
            temp.path().join("empty"),
            DecodePolicy::default().allow_gnu(false),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn vendor_pax_policy_covers_both_scopes_positions_and_opt_in() {
    let temp = tempdir().unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &pax_record("Acme.attribute", "value"))
        .posix("file", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(temp.path().join("local"), DecodePolicy::default())
            .await,
        Err(DecodeError::PolicyViolation {
            position: 0,
            violation: DecodePolicyViolation::PaxVendorExtension {
                vendor,
                name,
            },
        }) if vendor == "Acme" && name == "attribute"
    ));

    let destination = temp.path().join("partial");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("created", b'0', b"kept", "", 0o644)
        .pax(b'g', &pax_record("Acme.attribute", "value"))
        .posix("blocked", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(
                &destination,
                DecodePolicy::default()
                    .pax_policy(PaxDecodePolicy::default().allow_global_pax_extensions(true),),
            )
            .await,
        Err(DecodeError::PolicyViolation {
            position: 1024,
            violation: DecodePolicyViolation::PaxVendorExtension { .. },
        })
    ));
    assert_eq!(
        std::fs::read_to_string(destination.join("created")).unwrap(),
        "kept"
    );

    let destination = temp.path().join("permitted");
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &pax_record("Acme.attribute", "value"))
        .posix("file", b'0', b"ok", "", 0o644);
    let bytes = archive.finish();
    let policy = DecodePolicy::default()
        .pax_policy(PaxDecodePolicy::default().allow_unknown_pax_vendor_records(true));
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("file")).unwrap(),
        "ok"
    );
}

#[tokio::test]
async fn duplicate_pax_records_are_rejected_by_default_and_can_use_last_value() {
    let temp = tempdir().unwrap();
    let mut local = pax_record("path", "wrong");
    local.extend_from_slice(&pax_record("path", "actual"));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &local)
        .posix("raw", b'0', b"contents", "", 0o644);
    let bytes = archive.finish();

    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(temp.path().join("rejected"), DecodePolicy::default())
            .await,
        Err(DecodeError::PolicyViolation {
            position: 0,
            violation: DecodePolicyViolation::DuplicatePaxRecord { keyword },
        }) if keyword == "path"
    ));

    let destination = temp.path().join("permitted");
    let policy = DecodePolicy::default()
        .pax_policy(PaxDecodePolicy::default().allow_duplicate_pax_records(true));
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("actual")).unwrap(),
        "contents"
    );
    assert!(!destination.join("wrong").exists());
}

#[tokio::test]
async fn pax_extension_size_limit_is_configurable_for_extraction() {
    let temp = tempdir().expect("temporary directory should be created");
    let mut payload = pax_record("comment", "metadata");
    payload.extend_from_slice(&pax_record("mtime", "1"));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &payload)
        .posix("file", b'0', b"contents", "", 0o644);
    let bytes = archive.finish();
    let payload_size = u64::try_from(payload.len()).expect("payload size should fit u64");

    let destination = temp.path().join("rejected");
    let policy = DecodePolicy::default()
        .pax_policy(PaxDecodePolicy::default().max_extension_size(payload_size - 1));
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await,
        Err(DecodeError::Framing(FrameError {
            position: 0,
            inner: FrameErrorInner::PaxExtensionTooLarge { size, limit },
        })) if size == payload_size && limit == payload_size - 1
    ));
    assert!(destination.is_dir());
    assert!(
        std::fs::read_dir(destination)
            .expect("rejected destination should be readable")
            .next()
            .is_none()
    );

    let destination = temp.path().join("accepted");
    let policy = DecodePolicy::default()
        .pax_policy(PaxDecodePolicy::default().max_extension_size(payload_size));
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .expect("extension at configured limit should extract");
    assert_eq!(
        std::fs::read_to_string(destination.join("file"))
            .expect("extracted file should be readable"),
        "contents"
    );
}

#[tokio::test]
async fn global_pax_headers_support_opt_out_and_ignore_trailing_updates() {
    let temp = tempdir().unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &pax_record("comment", "metadata"))
        .posix("file", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let reject_globals = DecodePolicy::default()
        .pax_policy(PaxDecodePolicy::default().allow_global_pax_extensions(false));
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(temp.path().join("rejected"), reject_globals)
            .await,
        Err(DecodeError::PolicyViolation {
            position: 0,
            violation: DecodePolicyViolation::GlobalPaxExtension,
        })
    ));

    let destination = temp.path().join("permitted");
    let mut archive = ArchiveBuilder::new();
    archive.pax(b'g', &pax_record("comment", "metadata")).posix(
        "file",
        b'0',
        b"contents",
        "",
        0o644,
    );
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("file")).unwrap(),
        "contents"
    );

    let mut archive = ArchiveBuilder::new();
    archive.pax(b'g', &pax_record("comment", "metadata"));
    let trailing = archive.finish();
    Archive::new(trailing.as_slice())
        .extract(temp.path().join("trailing"), reject_globals)
        .await
        .unwrap();

    let mut archive = ArchiveBuilder::new();
    archive.pax(b'g', b"invalid");
    let malformed = archive.finish();
    assert!(matches!(
        Archive::new(malformed.as_slice())
            .extract(temp.path().join("malformed"), reject_globals)
            .await,
        Err(DecodeError::Framing(FrameError {
            position: 0,
            inner: FrameErrorInner::InvalidPaxRecords { .. },
        }))
    ));
}

#[tokio::test]
async fn global_member_metadata_requires_opt_in_and_uses_pax_precedence() {
    let temp = tempdir().unwrap();
    for (case, keyword, value) in [
        ("path", "path", "file"),
        ("linkpath", "linkpath", "target"),
        ("size", "size", "0"),
    ] {
        let mut archive = ArchiveBuilder::new();
        archive
            .pax(b'g', &pax_record(keyword, value))
            .posix("raw", b'0', b"", "", 0o644);
        let bytes = archive.finish();
        let policy = DecodePolicy::default()
            .pax_policy(PaxDecodePolicy::default().allow_global_pax_extensions(true));
        assert!(matches!(
            Archive::new(bytes.as_slice())
                .extract(temp.path().join(case), policy)
                .await,
            Err(DecodeError::PolicyViolation {
                position: 0,
                violation: DecodePolicyViolation::GlobalPaxMemberMetadata {
                    keyword: found,
                },
            }) if found == keyword
        ));
    }

    let destination = temp.path().join("updates");
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &pax_record("path", "old"))
        .pax(b'g', &pax_record("path", "current"))
        .posix("raw", b'0', b"contents", "", 0o644);
    let bytes = archive.finish();
    let policy = DecodePolicy::default().pax_policy(
        PaxDecodePolicy::default()
            .allow_global_pax_extensions(true)
            .allow_global_pax_member_metadata(true),
    );
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("current")).unwrap(),
        "contents"
    );
    assert!(!destination.join("old").exists());
}

#[tokio::test]
async fn binary_names_are_rejected_and_streaming_failures_preserve_prior_output() {
    let temp = tempdir().unwrap();

    let mut binary_path = pax_record("hdrcharset", "BINARY");
    binary_path.extend_from_slice(&raw_pax_record("path", &[0xff]));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &binary_path)
        .posix("raw", b'0', b"", "", 0o644);
    let binary = archive.finish();
    assert!(matches!(
        Archive::new(binary.as_slice())
            .extract(temp.path().join("binary"), DecodePolicy::default())
            .await,
        Err(DecodeError::InvalidUtf8 { field: "path", .. })
    ));

    let destination = temp.path().join("partial");
    let mut invalid = header(ArchiveFormat::Posix, "bad", b'0', 0, "", 0o644);
    set_identity_byte(&mut invalid, 0, b'!');
    set_checksum(&mut invalid);
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("created", b'0', b"kept", "", 0o644)
        .block(&invalid);
    let bytes = archive.into_unterminated();
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, DecodePolicy::default())
            .await,
        Err(DecodeError::Framing(_))
    ));
    assert_eq!(
        std::fs::read_to_string(destination.join("created")).unwrap(),
        "kept"
    );
}
