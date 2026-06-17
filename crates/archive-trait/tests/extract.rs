pub mod support;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use archive_trait::{
    Archive as _, ExtractError, ExtractPolicyViolation, SpecialKind,
    extract::{ExtractPolicy, LinkPolicy, SymlinkPolicy},
};
use support::{TestArchive, entry};
use tempfile::tempdir;

#[tokio::test]
async fn extracts_common_members_and_streams_payload_sizes() {
    const SMALL_BYTES: usize = 128 * 1024 + 7;
    const LARGE_BYTES: usize = 1024 * 1024 + 7;

    let small = patterned_payload(SMALL_BYTES);
    let large = patterned_payload(LARGE_BYTES);
    let archive = TestArchive::new([
        entry::directory("bin"),
        entry::executable("bin/tool", b"run"),
        entry::file("same", b"old"),
        entry::file("same", b"new"),
        entry::file("small", small.clone()),
        entry::file("large", large.clone()),
    ]);
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");

    archive
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("archive should extract");

    for (path, expected) in [
        ("bin/tool", &b"run"[..]),
        ("same", &b"new"[..]),
        ("small", small.as_slice()),
        ("large", large.as_slice()),
    ] {
        assert_eq!(
            std::fs::read(destination.join(path)).expect("file should be readable"),
            expected
        );
    }
    #[cfg(unix)]
    {
        assert_ne!(
            std::fs::metadata(destination.join("bin/tool"))
                .expect("tool metadata should be readable")
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}

fn patterned_payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| u8::try_from(index % 251).expect("payload byte should fit"))
        .collect()
}

#[tokio::test]
async fn name_validation_covers_member_and_link_values() {
    let temp = tempdir().expect("temporary directory should be created");
    let policy = ExtractPolicy::default().link_policy(
        LinkPolicy::default()
            .allow_hard_links(true)
            .symlink_policy(SymlinkPolicy::Skip),
    );
    for (case, member, context) in [
        ("member", entry::file(" rejected", b""), "member path"),
        (
            "symbolic",
            entry::symbolic_link("link", " rejected"),
            "symbolic-link target",
        ),
        (
            "hard",
            entry::hard_link("link", " rejected", b""),
            "hard-link target",
        ),
    ] {
        assert!(matches!(
            TestArchive::new([member])
                .extract_in(temp.path().join(case), policy)
                .await,
            Err(ExtractError::PolicyViolation {
                violation: ExtractPolicyViolation::NameRejected {
                    context: actual,
                    ..
                },
                ..
            }) if actual == context
        ));
    }

    let destination = temp.path().join("disabled");
    TestArchive::new([entry::file(" allowed", b"ok")])
        .extract_in(&destination, ExtractPolicy::default().name_validator(None))
        .await
        .expect("disabled validation should accept boundary whitespace");
    assert_eq!(
        std::fs::read(destination.join(" allowed")).expect("file should be readable"),
        b"ok"
    );
}

#[tokio::test]
async fn validates_empty_payload_before_creating_file() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");

    let result = TestArchive::new([entry::invalid_file("invalid", b"")])
        .extract_in(&destination, ExtractPolicy::default())
        .await;

    assert!(matches!(result, Err(ExtractError::Archive(_))));
    assert!(!destination.join("invalid").exists());
}

#[tokio::test]
async fn rejects_invalid_destinations_unsafe_special_and_colliding_members() {
    let temp = tempdir().expect("temporary directory should be created");
    let file_destination = temp.path().join("file-destination");
    std::fs::write(&file_destination, b"keep").expect("destination file should be written");
    assert!(matches!(
        TestArchive::new([entry::file("file", b"archive")])
            .extract_in(&file_destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::Filesystem { .. })
    ));
    assert_eq!(
        std::fs::read(&file_destination).expect("destination file should remain readable"),
        b"keep"
    );

    for (case, path) in [
        ("leading-parent", "../escape"),
        ("absolute", "/escape"),
        ("backslash", r"nested\escape"),
    ] {
        assert!(matches!(
            TestArchive::new([entry::file(path, b"")])
                .extract_in(
                    temp.path().join(case),
                    ExtractPolicy::default().name_validator(None),
                )
                .await,
            Err(ExtractError::UnsafePath { .. })
        ));
    }
    assert!(!temp.path().join("escape").exists());

    assert!(matches!(
        TestArchive::new([entry::special("device", SpecialKind::CharacterDevice)])
            .extract_in(temp.path().join("special"), ExtractPolicy::default())
            .await,
        Err(ExtractError::UnsupportedMember {
            kind: SpecialKind::CharacterDevice,
            ..
        })
    ));

    let destination = temp.path().join("collision");
    std::fs::create_dir(&destination).expect("destination should be created");
    std::fs::write(destination.join("file"), b"ambient").expect("ambient file should be written");
    assert!(matches!(
        TestArchive::new([entry::file("file", b"archive")])
            .extract_in(
                &destination,
                ExtractPolicy::default().allow_overwrites(false),
            )
            .await,
        Err(ExtractError::PathCollision { path }) if path == Path::new("file")
    ));
}

#[tokio::test]
async fn archive_errors_preserve_prior_streaming_output() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("partial");
    let result = TestArchive::new([entry::file("created", b"kept"), entry::error()])
        .extract_in(&destination, ExtractPolicy::default())
        .await;

    assert!(matches!(result, Err(ExtractError::Archive(_))));
    assert_eq!(
        std::fs::read(destination.join("created")).expect("created file should remain"),
        b"kept"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn destination_junctions_are_rejected_as_parents_and_roots() {
    let temp = tempdir().expect("temporary directory should be created");
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside).expect("outside directory should be created");
    std::fs::write(outside.join("keep"), b"keep").expect("outside file should be written");

    let destination = temp.path().join("parent");
    std::fs::create_dir(&destination).expect("destination should be created");
    junction::create(&outside, destination.join("junction"))
        .expect("parent junction should be created");
    assert!(matches!(
        TestArchive::new([entry::file("junction/file", b"archive")])
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::PathCollision { path }) if path == Path::new("junction")
    ));
    assert!(!outside.join("file").exists());

    let destination = temp.path().join("root-junction");
    junction::create(&outside, &destination).expect("root junction should be created");
    assert!(matches!(
        TestArchive::new([entry::file("file", b"archive")])
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::Filesystem { .. })
    ));
    assert_eq!(
        std::fs::read(outside.join("keep")).expect("outside file should remain readable"),
        b"keep"
    );
    assert!(!outside.join("file").exists());
}
