pub mod support;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use archive_trait::{Archive as _, ExtractError, ExtractPolicy, SpecialKind};
use support::{Entry, TestArchive};
use tempfile::tempdir;

#[tokio::test]
async fn extracts_common_members_and_streams_large_payloads() {
    const LARGE_BYTES: usize = 1024 * 1024 + 7;

    let large = (0..LARGE_BYTES)
        .map(|index| u8::try_from(index % 251).expect("payload byte should fit"))
        .collect::<Vec<_>>();
    let archive = TestArchive::new([
        Entry::directory("bin"),
        Entry::executable("bin/tool", b"run"),
        Entry::file("same", b"old"),
        Entry::file("same", b"new"),
        Entry::file("large", large.clone()),
    ]);
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");

    archive
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("archive should extract");

    assert_eq!(
        std::fs::read(destination.join("bin/tool")).expect("tool should be readable"),
        b"run"
    );
    assert_eq!(
        std::fs::read(destination.join("same")).expect("replacement should be readable"),
        b"new"
    );
    assert_eq!(
        std::fs::read(destination.join("large")).expect("large file should be readable"),
        large
    );
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

#[tokio::test]
async fn rejects_unsafe_special_and_colliding_members() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("unsafe");
    assert!(matches!(
        TestArchive::new([Entry::file("../escape", b"")])
            .extract_in(&destination, ExtractPolicy::default().name_validator(None))
            .await,
        Err(ExtractError::UnsafePath { .. })
    ));
    assert!(!temp.path().join("escape").exists());

    assert!(matches!(
        TestArchive::new([Entry::special("device", SpecialKind::CharacterDevice)])
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
        TestArchive::new([Entry::file("file", b"archive")])
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
    let result = TestArchive::new([Entry::file("created", b"kept"), Entry::Error])
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
        TestArchive::new([Entry::file("junction/file", b"archive")])
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::PathCollision { path }) if path == Path::new("junction")
    ));
    assert!(!outside.join("file").exists());

    let destination = temp.path().join("root-junction");
    junction::create(&outside, &destination).expect("root junction should be created");
    assert!(matches!(
        TestArchive::new([Entry::file("file", b"archive")])
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
