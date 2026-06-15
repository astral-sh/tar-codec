pub mod support;

#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::path::Path;

use support::{ArchiveBuilder, pax_record, single_posix_member};
use tar_codec::decode::{Archive, DecodeError, DecodePolicy, DecodePolicyViolation, LinkPolicy};
use tar_framing::PaxKeyword;
use tempfile::tempdir;

#[tokio::test]
async fn materializes_safe_symlink_chains_and_forward_references() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("dir/file", b'0', b"ok", "", 0o644)
        .posix("dir/one", b'2', b"", "file", 0o644)
        .posix("dir/exact", b'2', b"", "./file", 0o644)
        .posix("two", b'2', b"", "dir/one", 0o644)
        .posix("forward", b'2', b"", "later", 0o644)
        .posix("later", b'0', b"later", "", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    for path in ["dir/one", "dir/exact", "two"] {
        assert_eq!(std::fs::read(destination.join(path)).unwrap(), b"ok");
        assert!(
            std::fs::symlink_metadata(destination.join(path))
                .unwrap()
                .is_file()
        );
    }
    assert_eq!(
        std::fs::read(destination.join("forward")).unwrap(),
        b"later"
    );
    std::fs::write(destination.join("dir/file"), b"changed").unwrap();
    assert_eq!(std::fs::read(destination.join("two")).unwrap(), b"ok");

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        assert_ne!(
            std::fs::metadata(destination.join("dir/file"))
                .unwrap()
                .ino(),
            std::fs::metadata(destination.join("dir/one"))
                .unwrap()
                .ino()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn creates_exact_and_opt_in_dangling_native_symlink_chains() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("dangling");
    std::fs::create_dir_all(destination.join("ambient")).unwrap();
    let bytes = single_posix_member("link", b'2', b"", "ambient/missing", 0o644);
    Archive::new(bytes.as_slice())
        .extract(
            &destination,
            DecodePolicy::default().link_policy(
                LinkPolicy::default()
                    .create_symlinks(true)
                    .allow_missing_targets(true),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("link")).unwrap(),
        Path::new("ambient/missing")
    );

    let destination = temp.path().join("dangling-chain");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("one", b'2', b"", "two", 0o644)
        .posix("two", b'2', b"", "missing", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(
            &destination,
            DecodePolicy::default().link_policy(
                LinkPolicy::default()
                    .create_symlinks(true)
                    .allow_missing_targets(true),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("one")).unwrap(),
        Path::new("two")
    );
    assert_eq!(
        std::fs::read_link(destination.join("two")).unwrap(),
        Path::new("missing")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn preserves_directory_required_symlink_targets_and_rejects_file_targets() {
    let temp = tempdir().expect("temporary directory should be created");
    let policy = DecodePolicy::default().link_policy(LinkPolicy::default().create_symlinks(true));
    for (case, target) in [("separator", "target/"), ("dot", "target/.")] {
        let destination = temp.path().join(format!("directory-{case}"));
        let mut archive = ArchiveBuilder::new();
        archive
            .posix("target", b'5', b"", "", 0o755)
            .pax(b'x', &pax_record(PaxKeyword::LinkPath, target))
            .posix("link", b'2', b"", "ignored", 0o644);
        let bytes = archive.finish();
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await
            .expect("directory-required target should resolve to a directory");
        assert_eq!(
            std::fs::read_link(destination.join("link"))
                .expect("symbolic link should be readable")
                .as_os_str(),
            Path::new(target).as_os_str()
        );

        let destination = temp.path().join(format!("file-{case}"));
        let mut archive = ArchiveBuilder::new();
        archive
            .posix("target", b'0', b"contents", "", 0o644)
            .pax(b'x', &pax_record(PaxKeyword::LinkPath, target))
            .posix("link", b'2', b"", "ignored", 0o644);
        let bytes = archive.finish();
        assert!(matches!(
            Archive::new(bytes.as_slice())
                .extract(&destination, policy)
                .await,
            Err(DecodeError::InvalidLink {
                reason: "target path suffix requires a directory",
                ..
            })
        ));
        assert!(!destination.join("link").exists());
        assert_eq!(
            std::fs::read(destination.join("target"))
                .expect("previous target payload should remain"),
            b"contents"
        );
    }
}

#[tokio::test]
async fn rejects_ambiguous_parent_directory_traversal_in_pax_symlink_targets() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("regular", b'0', b"regular", "", 0o644)
        .posix("secret", b'0', b"secret", "", 0o600)
        .pax(b'x', &pax_record(PaxKeyword::LinkPath, "regular/../secret"))
        .posix("link", b'2', b"", "ignored", 0o644);
    let bytes = archive.finish();

    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, DecodePolicy::default())
            .await,
        Err(DecodeError::UnsafePath {
            context: "symbolic-link target",
            reason: "contains ambiguous parent-directory traversal",
            ..
        })
    ));
    assert!(!destination.join("link").exists());
}

#[tokio::test]
async fn default_materialization_rejects_non_file_targets() {
    let temp = tempdir().unwrap();
    for (case, target, directory_target) in [
        ("missing", "missing", false),
        ("root", ".", false),
        ("directory", "directory", true),
    ] {
        let destination = temp.path().join(case);
        let bytes = if directory_target {
            let mut archive = ArchiveBuilder::new();
            archive
                .posix("directory", b'5', b"", "", 0o755)
                .posix("link", b'2', b"", target, 0o644);
            archive.finish()
        } else {
            single_posix_member("link", b'2', b"", target, 0o644)
        };
        assert!(matches!(
            Archive::new(bytes.as_slice())
                .extract(&destination, DecodePolicy::default())
                .await,
            Err(DecodeError::InvalidLink { .. })
        ));
        assert!(!destination.join("link").exists());
    }

    let destination = temp.path().join("directory-required-file");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("file", b'0', b"contents", "", 0o644)
        .posix("link", b'2', b"", "file/", 0o644);
    let bytes = archive.finish();
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, DecodePolicy::default())
            .await,
        Err(DecodeError::InvalidLink {
            reason: "target path suffix requires a directory",
            ..
        })
    ));
}

#[tokio::test]
async fn missing_targets_cannot_be_materialized() {
    let temp = tempdir().unwrap();
    let bytes = single_posix_member("link", b'2', b"", "missing", 0o644);
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(
                temp.path(),
                DecodePolicy::default()
                    .link_policy(LinkPolicy::default().allow_missing_targets(true)),
            )
            .await,
        Err(DecodeError::InvalidLink {
            reason: "materialization target does not exist",
            ..
        })
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn native_target_controls_are_independent() {
    let temp = tempdir().unwrap();

    let destination = temp.path().join("missing-only");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("ambient"), b"ambient").unwrap();
    let bytes = single_posix_member("link", b'2', b"", "ambient", 0o644);
    let policy = DecodePolicy::default().link_policy(
        LinkPolicy::default()
            .create_symlinks(true)
            .allow_missing_targets(true),
    );
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await,
        Err(DecodeError::InvalidLink {
            reason: "ambient target is not allowed",
            ..
        })
    ));

    let destination = temp.path().join("ambient-allowed");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("ambient"), b"ambient").unwrap();
    let bytes = single_posix_member("link", b'2', b"", "ambient", 0o644);
    let policy = DecodePolicy::default().link_policy(
        LinkPolicy::default()
            .create_symlinks(true)
            .allow_ambient_targets(true),
    );
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("link")).unwrap(),
        Path::new("ambient")
    );

    let destination = temp.path().join("ambient-only");
    let bytes = single_posix_member("link", b'2', b"", "missing", 0o644);
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await,
        Err(DecodeError::InvalidLink {
            reason: "target does not exist",
            ..
        })
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn materialized_links_inherit_the_targets_executable_intent() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempdir().unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("target", b'0', b"executable", "", 0o755)
        .posix("link", b'2', b"", "target", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(temp.path(), DecodePolicy::default())
        .await
        .unwrap();
    assert_ne!(
        std::fs::metadata(temp.path().join("link"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
}

#[cfg(windows)]
#[tokio::test]
async fn native_symlink_creation_is_rejected_only_when_a_link_is_encountered() {
    let temp = tempdir().unwrap();
    let policy = DecodePolicy::default().link_policy(LinkPolicy::default().create_symlinks(true));
    let regular = single_posix_member("file", b'0', b"contents", "", 0o644);
    Archive::new(regular.as_slice())
        .extract(temp.path().join("regular"), policy)
        .await
        .unwrap();

    let mut archive = ArchiveBuilder::new();
    archive
        .posix("target", b'0', b"contents", "", 0o644)
        .posix("link", b'2', b"", "target", 0o644);
    let bytes = archive.finish();
    let destination = temp.path().join("link");
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await,
        Err(DecodeError::PolicyViolation {
            position: 1024,
            violation: DecodePolicyViolation::NativeSymlinkCreationUnsupported,
        })
    ));
    assert_eq!(
        std::fs::read(destination.join("target")).unwrap(),
        b"contents"
    );
    assert!(!destination.join("link").exists());
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn ambient_file_and_directory_targets_require_explicit_opt_in() {
    let temp = tempdir().unwrap();
    for (kind, directory) in [("file", false), ("directory", true)] {
        for allow_ambient in [false, true] {
            let destination = temp.path().join(format!(
                "{kind}-{}",
                if allow_ambient { "allow" } else { "deny" }
            ));
            std::fs::create_dir(&destination).unwrap();
            let target = destination.join("ambient");
            if directory {
                std::fs::create_dir(&target).unwrap();
            } else {
                std::fs::write(&target, b"ambient").unwrap();
            }
            let bytes = single_posix_member("link", b'2', b"", "ambient", 0o644);
            let policy = if allow_ambient {
                DecodePolicy::default()
                    .link_policy(LinkPolicy::default().allow_ambient_targets(true))
            } else {
                DecodePolicy::default()
            };
            let result = Archive::new(bytes.as_slice())
                .extract(&destination, policy)
                .await;
            if allow_ambient && !directory {
                result.unwrap();
                assert_eq!(std::fs::read(destination.join("link")).unwrap(), b"ambient");
                assert!(destination.join("link").is_file());
            } else {
                assert!(matches!(result, Err(DecodeError::InvalidLink { .. })));
                assert!(!destination.join("link").exists());
            }
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn materialization_rejects_ambient_non_regular_files() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    std::fs::create_dir(&destination).unwrap();
    let _socket = UnixListener::bind(destination.join("socket")).unwrap();
    let bytes = single_posix_member("link", b'2', b"", "socket", 0o644);
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(
                &destination,
                DecodePolicy::default()
                    .link_policy(LinkPolicy::default().allow_ambient_targets(true)),
            )
            .await,
        Err(DecodeError::InvalidLink {
            reason: "materialization target is not a regular file",
            ..
        })
    ));
    assert!(!destination.join("link").exists());
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn ambient_link_components_must_resolve_beneath_the_root() {
    use support::{symlink_dir, symlink_file};

    let temp = tempdir().unwrap();
    let policy =
        DecodePolicy::default().link_policy(LinkPolicy::default().allow_ambient_targets(true));

    let destination = temp.path().join("contained-leaf");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("target"), b"inside").unwrap();
    symlink_file(Path::new("target"), destination.join("ambient-link")).unwrap();
    let bytes = single_posix_member("alias", b'2', b"", "ambient-link", 0o644);
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(std::fs::read(destination.join("alias")).unwrap(), b"inside");

    let destination = temp.path().join("contained-intermediate");
    std::fs::create_dir_all(destination.join("target")).unwrap();
    std::fs::write(destination.join("target/file"), b"inside").unwrap();
    symlink_dir(Path::new("target"), destination.join("ambient-link")).unwrap();
    let bytes = single_posix_member("alias", b'2', b"", "ambient-link/file", 0o644);
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(std::fs::read(destination.join("alias")).unwrap(), b"inside");

    let destination = temp.path().join("leaf");
    let outside = temp.path().join("outside-file");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(&outside, b"outside").unwrap();
    symlink_file(&outside, destination.join("ambient-link")).unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("safe", b'0', b"safe", "", 0o644)
        .pax(b'x', &pax_record(PaxKeyword::LinkPath, "ambient-link"))
        .posix("alias", b'2', b"", "safe", 0o644);
    let bytes = archive.finish();
    assert!(
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await
            .is_err()
    );
    assert!(!destination.join("alias").exists());
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");

    let destination = temp.path().join("intermediate");
    let outside = temp.path().join("outside-directory");
    std::fs::create_dir(&destination).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("file"), b"outside").unwrap();
    symlink_dir(&outside, destination.join("ambient-link")).unwrap();
    let bytes = single_posix_member("alias", b'2', b"", "ambient-link/file", 0o644);
    assert!(
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await
            .is_err()
    );
    assert!(!destination.join("alias").exists());
}

#[cfg(windows)]
#[tokio::test]
async fn ambient_junction_components_outside_the_root_are_rejected() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("destination");
    let outside = temp.path().join("outside");
    std::fs::create_dir(&destination).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("file"), b"outside").unwrap();
    junction::create(&outside, destination.join("ambient-junction")).unwrap();

    let bytes = single_posix_member("alias", b'2', b"", "ambient-junction/file", 0o644);
    let policy =
        DecodePolicy::default().link_policy(LinkPolicy::default().allow_ambient_targets(true));
    assert!(
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await
            .is_err()
    );
    assert!(!destination.join("alias").exists());
    assert_eq!(std::fs::read(outside.join("file")).unwrap(), b"outside");
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn default_target_policy_uses_filesystem_provenance() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("declared-ambient-directory");
    std::fs::create_dir_all(destination.join("ambient")).unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("ambient", b'5', b"", "", 0o755)
        .posix("alias", b'2', b"", "ambient", 0o644);
    let bytes = archive.finish();
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, DecodePolicy::default())
            .await,
        Err(DecodeError::InvalidLink {
            reason: "target was not created by this extraction",
            ..
        })
    ));

    let destination = temp.path().join("created-file-under-ambient-directory");
    std::fs::create_dir_all(destination.join("ambient")).unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("ambient/file", b'0', b"archive", "", 0o644)
        .posix("alias", b'2', b"", "ambient/file", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(destination.join("alias")).unwrap(),
        b"archive"
    );
}

#[tokio::test]
async fn symlink_graphs_allow_finite_expansion_and_reject_cycles_and_escapes() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("finite");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("file", b'0', b"ok", "", 0o644)
        .posix("a", b'2', b"", "file", 0o644)
        .posix("b", b'2', b"", "a", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("b")).unwrap(),
        "ok"
    );

    for (case, first_target, second_target, expansion_limit) in [
        ("cycle", "b", "a", false),
        ("growing-cycle", "b/x", "a/y", true),
    ] {
        let destination = temp.path().join(case);
        let mut archive = ArchiveBuilder::new();
        archive.posix("a", b'2', b"", first_target, 0o644).posix(
            "b",
            b'2',
            b"",
            second_target,
            0o644,
        );
        let bytes = archive.finish();
        let error = Archive::new(bytes.as_slice())
            .extract(&destination, DecodePolicy::default())
            .await
            .unwrap_err();
        assert!(matches!(error, DecodeError::InvalidLink { .. }));
        if expansion_limit {
            assert!(matches!(
                error,
                DecodeError::InvalidLink {
                    reason: "symbolic-link target expansion limit exceeded",
                    ..
                }
            ));
        }
        assert!(!destination.join("a").exists());
        assert!(!destination.join("b").exists());
    }

    let destination = temp.path().join("escape");
    let bytes = single_posix_member("link", b'2', b"", "../outside", 0o644);
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, DecodePolicy::default())
            .await,
        Err(DecodeError::UnsafePath { .. })
    ));
    assert!(!destination.join("link").exists());
}

#[tokio::test]
async fn overwritten_pending_symlinks_do_not_affect_installation_or_resolution() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("obsolete", b'2', b"", "missing", 0o644)
        .posix("obsolete", b'0', b"file", "", 0o644)
        .posix("alias", b'2', b"", "target", 0o644)
        .posix("target", b'2', b"", "missing", 0o644)
        .posix("target", b'0', b"target", "", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(destination.join("obsolete")).unwrap(),
        b"file"
    );
    assert_eq!(std::fs::read(destination.join("alias")).unwrap(), b"target");
    assert!(destination.join("alias").is_file());
}

#[tokio::test]
async fn later_link_entries_replace_links_of_the_same_kind() {
    let temp = tempdir().unwrap();
    for (case, typeflag) in [("symbolic-link", b'2'), ("hard-link", b'1')] {
        let destination = temp.path().join(case);
        let mut archive = ArchiveBuilder::new();
        archive
            .posix("first", b'0', b"first", "", 0o644)
            .posix("second", b'0', b"second", "", 0o644)
            .posix("same", typeflag, b"", "first", 0o644)
            .posix("same", typeflag, b"", "second", 0o644);
        let bytes = archive.finish();
        Archive::new(bytes.as_slice())
            .extract(
                &destination,
                DecodePolicy::default().link_policy(LinkPolicy::default().allow_hard_links(true)),
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read(destination.join("same")).unwrap(), b"second");
        if typeflag == b'2' {
            assert!(destination.join("same").is_file());
        }
    }
}

#[tokio::test]
async fn hard_links_require_prior_archive_targets_and_apply_linkdata() {
    let temp = tempdir().unwrap();
    let policy = DecodePolicy::default().link_policy(LinkPolicy::default().allow_hard_links(true));
    let destination = temp.path().join("linkdata");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("a", b'0', b"old", "", 0o644)
        .posix("b", b'1', b"new", "a", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert_eq!(std::fs::read(destination.join("a")).unwrap(), b"new");
    assert_eq!(std::fs::read(destination.join("b")).unwrap(), b"new");

    let unresolved = single_posix_member("b", b'1', b"", "a", 0o644);
    assert!(matches!(
        Archive::new(unresolved.as_slice())
            .extract(temp.path().join("forward"), policy)
            .await,
        Err(DecodeError::InvalidLink { .. })
    ));

    let destination = temp.path().join("ambient");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("a"), b"ambient").unwrap();
    assert!(matches!(
        Archive::new(unresolved.as_slice())
            .extract(&destination, policy)
            .await,
        Err(DecodeError::InvalidLink { .. })
    ));
    assert_eq!(std::fs::read(destination.join("a")).unwrap(), b"ambient");
    assert!(!destination.join("b").exists());

    let destination = temp.path().join("different-mode");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("a", b'0', b"", "", 0o644)
        .posix("b", b'1', b"", "a", 0o755);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, policy)
        .await
        .unwrap();
    assert!(destination.join("b").is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let destination = temp.path().join("linkdata-mode");
        let mut archive = ArchiveBuilder::new();
        archive
            .posix("a", b'0', b"old", "", 0o644)
            .posix("b", b'1', b"new", "a", 0o755);
        let bytes = archive.finish();
        Archive::new(bytes.as_slice())
            .extract(&destination, policy)
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(destination.join("a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}

#[tokio::test]
async fn hard_links_cannot_replace_their_targets() {
    let temp = tempdir().unwrap();
    for (case, path) in [("self", "target"), ("ancestor", "target/link")] {
        let destination = temp.path().join(case);
        let mut archive = ArchiveBuilder::new();
        archive
            .posix("target", b'0', b"keep", "", 0o644)
            .posix(path, b'1', b"", "target", 0o644);
        let bytes = archive.finish();
        assert!(matches!(
            Archive::new(bytes.as_slice())
                .extract(
                    &destination,
                    DecodePolicy::default()
                        .link_policy(LinkPolicy::default().allow_hard_links(true)),
                )
                .await,
            Err(DecodeError::InvalidLink { .. })
        ));
        assert_eq!(std::fs::read(destination.join("target")).unwrap(), b"keep");
    }
}

#[tokio::test]
async fn link_policies_are_enforced_before_link_creation() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("symlink");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("target", b'0', b"ok", "", 0o644)
        .posix("link", b'2', b"", "target", 0o644);
    let bytes = archive.finish();
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(
                &destination,
                DecodePolicy::default().link_policy(
                    LinkPolicy::default()
                        .allow_symlinks(false)
                        .create_symlinks(true),
                ),
            )
            .await,
        Err(DecodeError::PolicyViolation {
            position: 1024,
            violation: DecodePolicyViolation::SymbolicLink,
        })
    ));
    assert_eq!(
        std::fs::read_to_string(destination.join("target")).unwrap(),
        "ok"
    );
    assert!(!destination.join("link").exists());

    let destination = temp.path().join("hard-link");
    let mut archive = ArchiveBuilder::new();
    archive.posix("target", b'0', b"keep", "", 0o644).posix(
        "link",
        b'1',
        b"untrusted linkdata",
        "target",
        0o644,
    );
    let bytes = archive.finish();
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(&destination, DecodePolicy::default())
            .await,
        Err(DecodeError::PolicyViolation {
            position: 1024,
            violation: DecodePolicyViolation::HardLink,
        })
    ));
    assert_eq!(
        std::fs::read_to_string(destination.join("target")).unwrap(),
        "keep"
    );
    assert!(!destination.join("link").exists());

    let destination = temp.path().join("hard-link-only");
    Archive::new(bytes.as_slice())
        .extract(
            &destination,
            DecodePolicy::default().link_policy(
                LinkPolicy::default()
                    .allow_symlinks(false)
                    .allow_hard_links(true),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(destination.join("target")).unwrap(),
        b"untrusted linkdata"
    );
    assert_eq!(
        std::fs::read(destination.join("link")).unwrap(),
        b"untrusted linkdata"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn native_symlink_and_hard_link_builders_compose() {
    let temp = tempdir().unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("target", b'0', b"contents", "", 0o644)
        .posix("symbolic", b'2', b"", "target", 0o644)
        .posix("hard", b'1', b"", "target", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(
            temp.path(),
            DecodePolicy::default().link_policy(
                LinkPolicy::default()
                    .create_symlinks(true)
                    .allow_hard_links(true),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(temp.path().join("symbolic")).unwrap(),
        Path::new("target")
    );
    std::fs::write(temp.path().join("target"), b"updated").unwrap();
    assert_eq!(
        std::fs::read(temp.path().join("symbolic")).unwrap(),
        b"updated"
    );
    assert_eq!(std::fs::read(temp.path().join("hard")).unwrap(), b"updated");
}
