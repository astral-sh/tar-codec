pub mod support;

use std::path::Path;

use support::{ArchiveBuilder, single_posix_member};
use tar_codec::decode::{Archive, DecodeError, DecodePolicy, DecodePolicyViolation};
use tempfile::tempdir;

#[tokio::test]
async fn creates_safe_normalized_and_dangling_symlink_chains() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("safe");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("dir/file", b'0', b"ok", "", 0o644)
        .posix("dir/one", b'2', b"", "file", 0o644)
        .posix("dir/normalized", b'2', b"", "./sub/../file", 0o644)
        .posix("two", b'2', b"", "dir/one", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("two")).unwrap(),
        "ok"
    );
    assert_eq!(
        std::fs::read_link(destination.join("dir/normalized")).unwrap(),
        Path::new("file")
    );

    let destination = temp.path().join("dangling");
    let bytes = single_posix_member("link", b'2', b"", "missing", 0o644);
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("link")).unwrap(),
        Path::new("missing")
    );

    let destination = temp.path().join("dangling-chain");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("one", b'2', b"", "two", 0o644)
        .posix("two", b'2', b"", "missing", 0o644);
    let bytes = archive.finish();
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
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

#[tokio::test]
async fn strict_dangling_policy_accepts_the_root_but_rejects_missing_targets() {
    let temp = tempdir().unwrap();
    for (case, target, allowed) in [("missing", "missing", false), ("root", ".", true)] {
        let destination = temp.path().join(case);
        let bytes = single_posix_member("link", b'2', b"", target, 0o644);
        let result = Archive::new(bytes.as_slice())
            .extract(
                &destination,
                DecodePolicy::default().allow_dangling_symlinks(false),
            )
            .await;
        if allowed {
            result.unwrap();
            assert_eq!(
                std::fs::read_link(destination.join("link")).unwrap(),
                Path::new(target)
            );
        } else {
            assert!(matches!(result, Err(DecodeError::InvalidLink { .. })));
            assert!(!destination.join("link").exists());
        }
    }
}

#[tokio::test]
async fn symlink_graphs_allow_finite_expansion_and_reject_cycles_and_escapes() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("finite");
    let mut archive = ArchiveBuilder::new();
    archive
        .posix("file", b'0', b"ok", "", 0o644)
        .posix("a", b'2', b"", ".", 0o644)
        .posix("b", b'2', b"", "a/a/file", 0o644);
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
        .extract(
            &destination,
            DecodePolicy::default().allow_dangling_symlinks(false),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(destination.join("obsolete")).unwrap(),
        b"file"
    );
    assert_eq!(std::fs::read(destination.join("alias")).unwrap(), b"target");
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
            .extract(&destination, DecodePolicy::default().allow_hard_links(true))
            .await
            .unwrap();
        assert_eq!(std::fs::read(destination.join("same")).unwrap(), b"second");
    }
}

#[tokio::test]
async fn hard_links_require_prior_archive_targets_and_apply_linkdata() {
    let temp = tempdir().unwrap();
    let policy = DecodePolicy::default().allow_hard_links(true);
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
                .extract(&destination, DecodePolicy::default().allow_hard_links(true),)
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
            .extract(&destination, DecodePolicy::default().allow_symlinks(false),)
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
}
