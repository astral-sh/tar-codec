pub mod support;

use std::path::Path;

#[cfg(unix)]
use support::EntryKind;
use support::{ArchiveBuilder, ArchiveFormat, header, pax_record, single_posix_member};
#[cfg(unix)]
use tar_codec::extract::LinkPolicy;
use tar_codec::{Archive as _, DecodeError, ExtractError, TarArchive, extract::ExtractPolicy};
use tar_framing::{FrameError, FrameErrorInner, PaxKeyword, UstarKind};
use tempfile::tempdir;

#[tokio::test]
async fn extracts_files_directories_large_payloads_and_archive_path_syntax() {
    const LARGE_PAYLOAD_BYTES: usize = 1024 * 1024 + 7;

    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    let large_payload = (0..LARGE_PAYLOAD_BYTES)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect::<Vec<_>>();
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("bin/tool", b'0', b"run", "", 0o755)
        .posix("bin", b'5', b"", "", 0o755)
        .posix("empty/", b'5', b"", "", 0o755)
        .posix(".", b'5', b"", "", 0o755)
        .posix("large", b'0', &large_payload, "", 0o644);
    #[cfg(unix)]
    archive
        .posix("tests/snippets/ballon:main.py", b'0', b"ok", "", 0o644)
        .posix("C:/target", b'0', b"ok", "", 0o644);
    let bytes = archive.finish();

    std::fs::create_dir_all(destination.join("large")).unwrap();
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .unwrap();
    assert_eq!(std::fs::read(destination.join("bin/tool")).unwrap(), b"run");
    assert!(destination.join("empty").is_dir());
    assert_eq!(
        std::fs::read(destination.join("large")).unwrap(),
        large_payload
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_ne!(
            std::fs::metadata(destination.join("bin/tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
        for path in ["tests/snippets/ballon:main.py", "C:/target"] {
            assert_eq!(
                std::fs::read_to_string(destination.join(path)).unwrap(),
                "ok"
            );
        }
    }
}

/// Ensures that we reject a directory entry with a declared size that embeds a regular file.
/// See malo's `malicious/dir_with_embedded_header.tar` for the case that this was derived from.
/// See: <https://github.com/fastzip/malo/tree/3df544f1a2fc498b2a84eb34981deb111cadbf32/tar/malicious>
#[tokio::test]
async fn rejects_directory_payload_without_writing_embedded_members() {
    let embedded_header = header(ArchiveFormat::Pax, "embedded.txt", b'0', 5, "", 0o644);
    let mut archive = ArchiveBuilder::new();
    archive.posix("dir/", b'5', &embedded_header, "", 0o755);
    let bytes = archive.finish();

    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::Archive(DecodeError::Framing(FrameError {
            position: 0,
            inner: FrameErrorInner::InvalidMemberSize {
                kind: UstarKind::Directory,
                size: 512,
            },
        })))
    ));
    assert!(destination.is_dir());
    assert!(std::fs::read_dir(destination).unwrap().next().is_none());
}

/// Ensures that we reject a regular file with a directory-required path suffix.
/// See malo's `malicious/pax_path_trailoing_slash_file.tar` for the case
/// that this was derived from.
/// See: <https://github.com/fastzip/malo/tree/3df544f1a2fc498b2a84eb34981deb111cadbf32/tar/malicious>
#[tokio::test]
async fn rejects_directory_required_suffix_on_regular_file_without_writing_members() {
    for path in [
        "file.txt/",
        "file.txt/.",
        "file.txt//.",
        "file.txt/././.",
        "file.txt/./././",
        "foo/bar/..",
        "foo/bar/../",
    ] {
        let mut archive = ArchiveBuilder::new();
        archive
            .pax(b'x', &pax_record(PaxKeyword::Path, path))
            .posix("ignored", b'0', b"hello", "", 0o644);
        let bytes = archive.finish();

        let temp = tempdir().expect("temporary directory should be created");
        let destination = temp.path().join("out");
        assert!(matches!(
            TarArchive::new(bytes.as_slice())
                .extract_in(&destination, ExtractPolicy::default())
                .await,
            Err(ExtractError::UnsafePath {
                position: 1024,
                context: "member path",
                value,
                reason: "only a directory may have a directory-required path suffix",
            }) if value == path
        ));
        assert!(destination.is_dir());
        assert!(
            std::fs::read_dir(destination)
                .expect("destination should be readable")
                .next()
                .is_none()
        );
    }
}

#[tokio::test]
async fn accepts_directory_required_suffix_on_directory_members() {
    for path in [
        "directory/.",
        "directory//.",
        "directory/././.",
        "directory/./././",
    ] {
        let mut archive = ArchiveBuilder::new();
        archive
            .pax(b'x', &pax_record(PaxKeyword::Path, path))
            .posix("ignored", b'5', b"", "", 0o755);
        let bytes = archive.finish();

        let temp = tempdir().expect("temporary directory should be created");
        let destination = temp.path().join("out");
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await
            .expect("directory member should be extracted");
        assert!(destination.join("directory").is_dir());
    }
}

#[tokio::test]
async fn later_entries_replace_duplicate_normalized_and_ambient_files() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("ambient"), b"ambient").unwrap();

    let mut archive = ArchiveBuilder::new();
    archive
        .posix("same", b'0', b"old", "", 0o644)
        .posix("same", b'0', b"new", "", 0o644)
        .posix("nested//./normalized", b'0', b"old", "", 0o644)
        .posix("nested/normalized", b'0', b"new", "", 0o644)
        .posix("ambient", b'0', b"archive", "", 0o644);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .unwrap();

    assert_eq!(std::fs::read(destination.join("same")).unwrap(), b"new");
    assert_eq!(
        std::fs::read(destination.join("nested/normalized")).unwrap(),
        b"new"
    );
    assert_eq!(
        std::fs::read(destination.join("ambient")).unwrap(),
        b"archive"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn ambient_file_replacement_unlinks_the_inode_and_applies_mode() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("same"), b"ambient").unwrap();
    std::fs::hard_link(destination.join("same"), destination.join("sibling")).unwrap();
    let bytes = single_posix_member("same", b'0', b"archive", "", 0o755);

    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .unwrap();
    assert_eq!(std::fs::read(destination.join("same")).unwrap(), b"archive");
    assert_eq!(
        std::fs::read(destination.join("sibling")).unwrap(),
        b"ambient"
    );
    let replaced = std::fs::metadata(destination.join("same")).unwrap();
    let sibling = std::fs::metadata(destination.join("sibling")).unwrap();
    assert_ne!(replaced.ino(), sibling.ino());
    assert_ne!(replaced.permissions().mode() & 0o111, 0);
}

#[cfg(unix)]
#[tokio::test]
async fn later_entries_replace_representative_cross_kind_paths() {
    let temp = tempdir().unwrap();
    for (case, first, last) in [
        ("file-to-directory", EntryKind::File, EntryKind::Directory),
        ("directory-to-file", EntryKind::Directory, EntryKind::File),
        (
            "file-to-symbolic-link",
            EntryKind::File,
            EntryKind::SymbolicLink,
        ),
        (
            "symbolic-link-to-hard-link",
            EntryKind::SymbolicLink,
            EntryKind::HardLink,
        ),
    ] {
        let destination = temp.path().join(case);
        let mut archive = ArchiveBuilder::new();
        archive
            .posix("target", b'0', b"target", "", 0o644)
            .entry("./same", first, b"first")
            .entry("same", last, b"last");
        let bytes = archive.finish();
        TarArchive::new(bytes.as_slice())
            .extract_in(
                &destination,
                ExtractPolicy::default().link_policy(LinkPolicy::default().allow_hard_links(true)),
            )
            .await
            .unwrap();
        match last {
            EntryKind::File => {
                assert_eq!(
                    std::fs::read(destination.join("same")).unwrap(),
                    b"last",
                    "{case}"
                );
            }
            EntryKind::Directory => assert!(destination.join("same").is_dir(), "{case}"),
            EntryKind::SymbolicLink => {
                assert_eq!(
                    std::fs::read_link(destination.join("same")).unwrap(),
                    Path::new("target"),
                    "{case}"
                );
            }
            EntryKind::HardLink => {
                std::fs::write(destination.join("target"), b"updated").unwrap();
                assert_eq!(
                    std::fs::read(destination.join("same")).unwrap(),
                    b"updated",
                    "{case}"
                );
            }
        }
    }
}

/// Ensures exact-path members can replace eligible leaves while descendants
/// cannot implicitly promote non-directory ancestors into directories.
///
/// The ancestor cases cover archive-created regular files, hard links, and
/// pending symbolic links, as well as an ambient regular file. The descendant
/// uses a PAX `path` override so the check applies to the effective member path.
#[cfg(unix)]
#[tokio::test]
async fn extraction_replaces_empty_leaves_but_rejects_non_directory_parents() {
    let temp = tempdir().unwrap();
    for (case, existing_file, archive_kind) in [
        ("file-to-directory", true, EntryKind::Directory),
        ("file-to-symbolic-link", true, EntryKind::SymbolicLink),
        ("directory-to-file", false, EntryKind::File),
        ("directory-to-hard-link", false, EntryKind::HardLink),
    ] {
        let destination = temp.path().join(case);
        std::fs::create_dir(&destination).unwrap();
        if existing_file {
            std::fs::write(destination.join("same"), b"ambient").unwrap();
        } else {
            std::fs::create_dir(destination.join("same")).unwrap();
        }
        let mut archive = ArchiveBuilder::new();
        archive
            .posix("target", b'0', b"target", "", 0o644)
            .entry("same", archive_kind, b"archive");
        let bytes = archive.finish();
        TarArchive::new(bytes.as_slice())
            .extract_in(
                &destination,
                ExtractPolicy::default().link_policy(LinkPolicy::default().allow_hard_links(true)),
            )
            .await
            .unwrap();
        match archive_kind {
            EntryKind::File => {
                assert_eq!(std::fs::read(destination.join("same")).unwrap(), b"archive");
            }
            EntryKind::Directory => assert!(destination.join("same").is_dir()),
            EntryKind::SymbolicLink => {
                assert_eq!(
                    std::fs::read_link(destination.join("same")).unwrap(),
                    Path::new("target")
                );
            }
            EntryKind::HardLink => {
                std::fs::write(destination.join("target"), b"updated").unwrap();
                assert_eq!(std::fs::read(destination.join("same")).unwrap(), b"updated");
            }
        }
    }

    for (case, parent) in [
        ("file-parent", EntryKind::File),
        ("symbolic-link-parent", EntryKind::SymbolicLink),
        ("hard-link-parent", EntryKind::HardLink),
    ] {
        let destination = temp.path().join(case);
        let mut archive = ArchiveBuilder::new();
        archive
            .posix("target", b'0', b"target", "", 0o644)
            .entry("parent", parent, b"old")
            .pax(b'x', &pax_record(PaxKeyword::Path, "parent/child"))
            .posix("ignored", b'0', b"new", "", 0o644);
        let bytes = archive.finish();
        assert!(matches!(
            TarArchive::new(bytes.as_slice())
                .extract_in(
                    &destination,
                    ExtractPolicy::default().link_policy(LinkPolicy::default().allow_hard_links(true)),
                )
                .await,
            Err(ExtractError::PathCollision { path }) if path == Path::new("parent")
        ));
        assert!(!destination.join("parent/child").exists());
        match parent {
            EntryKind::File => {
                assert_eq!(std::fs::read(destination.join("parent")).unwrap(), b"old");
            }
            EntryKind::HardLink => {
                assert_eq!(
                    std::fs::read(destination.join("parent")).unwrap(),
                    b"target"
                );
            }
            EntryKind::SymbolicLink => {
                assert!(!destination.join("parent").exists());
            }
            EntryKind::Directory => {}
        }
    }

    let destination = temp.path().join("ambient-parent");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("parent"), b"old").unwrap();
    let bytes = single_posix_member("parent/child", b'0', b"new", "", 0o644);
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::PathCollision { path }) if path == Path::new("parent")
    ));
    assert_eq!(std::fs::read(destination.join("parent")).unwrap(), b"old");
}

#[cfg(unix)]
#[tokio::test]
async fn disabled_overwrites_reject_replacements_but_reuse_directories() {
    let temp = tempdir().unwrap();
    let archives = [
        ("duplicate", false, {
            let mut archive = ArchiveBuilder::new();
            archive
                .posix("same", b'0', b"old", "", 0o644)
                .posix("same", b'0', b"new", "", 0o644);
            archive.finish()
        }),
        ("cross-kind", false, {
            let mut archive = ArchiveBuilder::new();
            archive
                .posix("same", b'0', b"old", "", 0o644)
                .posix("same", b'5', b"", "", 0o755);
            archive.finish()
        }),
        ("parent", false, {
            let mut archive = ArchiveBuilder::new();
            archive.posix("parent", b'0', b"old", "", 0o644).posix(
                "parent/child",
                b'0',
                b"new",
                "",
                0o644,
            );
            archive.finish()
        }),
        ("pending-symlink", false, {
            let mut archive = ArchiveBuilder::new();
            archive
                .posix("same", b'2', b"", "missing", 0o644)
                .posix("same", b'0', b"new", "", 0o644);
            archive.finish()
        }),
        (
            "ambient",
            true,
            single_posix_member("same", b'0', b"new", "", 0o644),
        ),
    ];
    for (case, preexisting_file, bytes) in archives {
        let destination = temp.path().join(case);
        if preexisting_file {
            std::fs::create_dir(&destination).unwrap();
            std::fs::write(destination.join("same"), b"ambient").unwrap();
        }
        assert!(matches!(
            TarArchive::new(bytes.as_slice())
                .extract_in(
                    &destination,
                    ExtractPolicy::default().allow_overwrites(false),
                )
                .await,
            Err(ExtractError::PathCollision { .. })
        ));
    }

    let destination = temp.path().join("directories");
    std::fs::create_dir_all(destination.join("same")).unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("same/child", b'0', b"new", "", 0o644)
        .posix("same", b'5', b"", "", 0o755)
        .posix("same", b'5', b"", "", 0o755);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(
            &destination,
            ExtractPolicy::default().allow_overwrites(false),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(destination.join("same/child")).unwrap(),
        b"new"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn non_empty_directories_are_never_replaced() {
    let temp = tempdir().unwrap();
    let archives = [
        ("archive-child", {
            let mut archive = ArchiveBuilder::new();
            archive
                .posix("same/child", b'0', b"keep", "", 0o644)
                .posix("same", b'0', b"replace", "", 0o644);
            archive.finish()
        }),
        ("pending-symlink-child", {
            let mut archive = ArchiveBuilder::new();
            archive
                .posix("same/link", b'2', b"", "missing", 0o644)
                .posix("same", b'0', b"replace", "", 0o644);
            archive.finish()
        }),
    ];
    for (case, bytes) in archives {
        let destination = temp.path().join(case);
        assert!(matches!(
            TarArchive::new(bytes.as_slice())
                .extract_in(&destination, ExtractPolicy::default())
                .await,
            Err(ExtractError::PathCollision { .. })
        ));
        assert!(destination.join("same").is_dir());
    }

    let destination = temp.path().join("ambient-child");
    std::fs::create_dir_all(destination.join("same")).unwrap();
    std::fs::write(destination.join("same/child"), b"keep").unwrap();
    let bytes = single_posix_member("same", b'0', b"replace", "", 0o644);
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::PathCollision { .. })
    ));
    assert!(destination.join("same").is_dir());
}

/// Ensures a destination symbolic link cannot be used or replaced as an
/// implicit parent, while an exact-path leaf link remains replaceable without
/// modifying the object it targets.
#[cfg(any(unix, windows))]
#[tokio::test]
async fn extraction_rejects_symlink_parents_and_replaces_symlink_leaves_without_following() {
    use support::{symlink_dir, symlink_file};

    let temp = tempdir().unwrap();
    let destination = temp.path().join("parents");
    let outside = temp.path().join("outside-directory");
    std::fs::create_dir_all(&destination).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    symlink_dir(&outside, destination.join("parent")).unwrap();
    let bytes = single_posix_member("parent/file", b'0', b"good", "", 0o644);
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::PathCollision { path }) if path == Path::new("parent")
    ));
    assert_eq!(
        std::fs::read_link(destination.join("parent")).unwrap(),
        outside
    );
    assert!(!outside.join("file").exists());

    let destination = temp.path().join("leaf");
    let outside = temp.path().join("outside-file");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(&outside, b"keep").unwrap();
    symlink_file(&outside, destination.join("same")).unwrap();
    let bytes = single_posix_member("same", b'0', b"archive", "", 0o644);
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .unwrap();
    assert_eq!(std::fs::read(destination.join("same")).unwrap(), b"archive");
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn rejects_a_symlink_destination_root_without_modifying_its_target() {
    use support::symlink_dir;

    let temp = tempdir().unwrap();
    let target = temp.path().join("target");
    let destination = temp.path().join("link");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("keep"), b"keep").unwrap();
    symlink_dir(&target, &destination).unwrap();
    let bytes = single_posix_member("file", b'0', b"archive", "", 0o644);

    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::Filesystem { .. })
    ));
    assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"keep");
    assert!(!target.join("file").exists());
}
