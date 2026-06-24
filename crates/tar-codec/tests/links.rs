pub mod support;

#[cfg(unix)]
use std::{io, os::unix::net::UnixListener, path::Path};

use support::{ArchiveBuilder, single_pax_member};
#[cfg(unix)]
use support::{pax_record, symlink_file};
#[cfg(not(unix))]
use tar_codec::ExtractPolicyViolation;
use tar_codec::{
    Archive as _, ExtractError, TarArchive,
    extract::{ExtractPolicy, LinkPolicy},
};
#[cfg(unix)]
use tar_framing::PaxKeyword;
use tempfile::tempdir;

#[cfg(unix)]
#[tokio::test]
async fn preserves_safe_symlink_chains_and_forward_references() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("dir/file", b'0', b"ok", "", 0o644)
        .ustar("dir/one", b'2', b"", "file", 0o644)
        .ustar("dir/exact", b'2', b"", "./file", 0o644)
        .ustar("two", b'2', b"", "dir/one", 0o644)
        .ustar("forward", b'2', b"", "later", 0o644)
        .ustar("later", b'0', b"later", "", 0o644);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .unwrap();
    for (path, target) in [
        ("dir/one", "file"),
        ("dir/exact", "./file"),
        ("two", "dir/one"),
        ("forward", "later"),
    ] {
        assert_eq!(
            std::fs::read_link(destination.join(path)).unwrap(),
            Path::new(target)
        );
    }
    assert_eq!(std::fs::read(destination.join("two")).unwrap(), b"ok");
    assert_eq!(
        std::fs::read(destination.join("forward")).unwrap(),
        b"later"
    );
    std::fs::write(destination.join("dir/file"), b"changed").unwrap();
    assert_eq!(std::fs::read(destination.join("two")).unwrap(), b"changed");
}

#[cfg(unix)]
#[tokio::test]
async fn preserves_dangling_symlink_chains_by_default() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("dangling");
    std::fs::create_dir_all(destination.join("ambient")).unwrap();
    let bytes = single_pax_member("link", b'2', b"", "ambient/missing", 0o644);
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("link")).unwrap(),
        Path::new("ambient/missing")
    );

    let destination = temp.path().join("dangling-chain");
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("one", b'2', b"", "two", 0o644)
        .ustar("two", b'2', b"", "missing", 0o644);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
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
    let policy = ExtractPolicy::default();
    for (case, target) in [("separator", "target/"), ("dot", "target/.")] {
        let destination = temp.path().join(format!("directory-{case}"));
        let mut archive = ArchiveBuilder::new();
        archive
            .ustar("target", b'5', b"", "", 0o755)
            .pax(b'x', &pax_record(PaxKeyword::LinkPath, target))
            .ustar("link", b'2', b"", "ignored", 0o644);
        let bytes = archive.finish();
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, policy)
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
            .ustar("target", b'0', b"contents", "", 0o644)
            .pax(b'x', &pax_record(PaxKeyword::LinkPath, target))
            .ustar("link", b'2', b"", "ignored", 0o644);
        let bytes = archive.finish();
        assert!(matches!(
            TarArchive::new(bytes.as_slice())
                .extract_in(&destination, policy)
                .await,
            Err(ExtractError::InvalidLink {
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

#[cfg(unix)]
#[tokio::test]
async fn rejects_ambiguous_parent_directory_traversal_in_pax_symlink_targets() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("regular", b'0', b"regular", "", 0o644)
        .ustar("secret", b'0', b"secret", "", 0o600)
        .pax(b'x', &pax_record(PaxKeyword::LinkPath, "regular/../secret"))
        .ustar("link", b'2', b"", "ignored", 0o644);
    let bytes = archive.finish();

    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::UnsafePath {
            context: "symbolic-link target",
            reason: "contains ambiguous parent-directory traversal",
            ..
        })
    ));
    assert!(!destination.join("link").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn default_preserves_links_to_missing_root_and_directory_targets() {
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
                .ustar("directory", b'5', b"", "", 0o755)
                .ustar("link", b'2', b"", target, 0o644);
            archive.finish()
        } else {
            single_pax_member("link", b'2', b"", target, 0o644)
        };
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_link(destination.join("link")).unwrap(),
            Path::new(target)
        );
    }

    let destination = temp.path().join("directory-required-file");
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("file", b'0', b"contents", "", 0o644)
        .ustar("link", b'2', b"", "file/", 0o644);
    let bytes = archive.finish();
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::InvalidLink {
            reason: "target path suffix requires a directory",
            ..
        })
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn targets_blocked_by_archive_files_are_dangling() {
    let temp = tempdir().unwrap();
    let mut archive = ArchiveBuilder::new();
    archive.ustar("file", b'0', b"contents", "", 0o644).ustar(
        "link",
        b'2',
        b"",
        "file/child",
        0o644,
    );
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(temp.path().join("allow"), ExtractPolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(temp.path().join("allow/link")).unwrap(),
        Path::new("file/child")
    );

    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(
                temp.path().join("deny"),
                ExtractPolicy::default()
                    .link_policy(LinkPolicy::default().allow_missing_targets(false)),
            )
            .await,
        Err(ExtractError::InvalidLink {
            reason: "target does not exist",
            ..
        })
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn missing_targets_can_be_forbidden() {
    let temp = tempdir().unwrap();
    let bytes = single_pax_member("link", b'2', b"", "missing", 0o644);
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(
                temp.path(),
                ExtractPolicy::default()
                    .link_policy(LinkPolicy::default().allow_missing_targets(false)),
            )
            .await,
        Err(ExtractError::InvalidLink {
            reason: "target was not created by this extraction",
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
    let bytes = single_pax_member("link", b'2', b"", "ambient", 0o644);
    let policy = ExtractPolicy::default();
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, policy)
            .await,
        Err(ExtractError::InvalidLink {
            reason: "ambient target is not allowed",
            ..
        })
    ));

    let destination = temp.path().join("ambient-allowed");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("ambient"), b"ambient").unwrap();
    let bytes = single_pax_member("link", b'2', b"", "ambient", 0o644);
    let policy = ExtractPolicy::default().link_policy(
        LinkPolicy::default()
            .allow_ambient_targets(true)
            .allow_missing_targets(false),
    );
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("link")).unwrap(),
        Path::new("ambient")
    );

    let destination = temp.path().join("ambient-only");
    let bytes = single_pax_member("link", b'2', b"", "missing", 0o644);
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, policy)
            .await,
        Err(ExtractError::InvalidLink {
            reason: "target does not exist",
            ..
        })
    ));
}

/// A missing-target opt-in must not classify paths through existing filesystem
/// symlinks as ordinary absent targets and bypass the ambient-target policy.
#[cfg(unix)]
#[tokio::test]
async fn missing_target_opt_in_does_not_allow_dangling_targets_through_ambient_symlinks() {
    let temp = tempdir().unwrap();
    for (case, ambient_target, archive_target) in [
        ("leaf", "missing", "ambient-link"),
        ("intermediate", "ambient", "ambient-link/missing"),
    ] {
        let destination = temp.path().join(case);
        std::fs::create_dir(&destination).unwrap();
        if case == "intermediate" {
            std::fs::create_dir(destination.join("ambient")).unwrap();
        }
        symlink_file(ambient_target, destination.join("ambient-link")).unwrap();
        let bytes = single_pax_member("link", b'2', b"", archive_target, 0o644);
        let policy = ExtractPolicy::default();

        assert!(matches!(
            TarArchive::new(bytes.as_slice())
                .extract_in(&destination, policy)
                .await,
            Err(ExtractError::InvalidLink {
                reason: "ambient target is not allowed",
                ..
            })
        ));
        assert!(matches!(
            std::fs::symlink_metadata(destination.join("link")),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        ));
        assert_eq!(
            std::fs::read_link(destination.join("ambient-link")).unwrap(),
            Path::new(ambient_target)
        );
    }
}

#[cfg(not(unix))]
#[tokio::test]
async fn symlink_members_fail_by_default_on_unsupported_platforms() {
    let temp = tempdir().unwrap();
    let regular = single_pax_member("file", b'0', b"contents", "", 0o644);
    TarArchive::new(regular.as_slice())
        .extract_in(temp.path().join("regular"), ExtractPolicy::default())
        .await
        .unwrap();

    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("target", b'0', b"contents", "", 0o644)
        .ustar("link", b'2', b"", "target", 0o644);
    let bytes = archive.finish();
    let destination = temp.path().join("link");
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::PolicyViolation {
            position: 1024,
            violation: ExtractPolicyViolation::NativeSymlinkCreationUnsupported,
        })
    ));
    assert_eq!(
        std::fs::read(destination.join("target")).unwrap(),
        b"contents"
    );
    assert!(!destination.join("link").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_graph_resolution_budget_is_shared_across_links() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(
            b'x',
            &pax_record(
                PaxKeyword::LinkPath,
                &format!("missing/{}leaf", "x/".repeat(300)),
            ),
        )
        .ustar("chain", b'2', b"", "fallback", 0o644);
    for index in 0..128 {
        archive.ustar(&format!("alias-{index}"), b'2', b"", "chain", 0o644);
    }
    let bytes = archive.finish();

    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::InvalidLink {
            reason: "symbolic-link target resolution work limit exceeded",
            ..
        })
    ));
    assert!(!destination.join("chain").exists());
    assert!(!destination.join("alias-0").exists());
}

#[cfg(unix)]
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
            let bytes = single_pax_member("link", b'2', b"", "ambient", 0o644);
            let policy = if allow_ambient {
                ExtractPolicy::default()
                    .link_policy(LinkPolicy::default().allow_ambient_targets(true))
            } else {
                ExtractPolicy::default()
            };
            let result = TarArchive::new(bytes.as_slice())
                .extract_in(&destination, policy)
                .await;
            if allow_ambient {
                result.unwrap();
                assert_eq!(
                    std::fs::read_link(destination.join("link")).unwrap(),
                    Path::new("ambient")
                );
            } else {
                assert!(matches!(result, Err(ExtractError::InvalidLink { .. })));
                assert!(!destination.join("link").exists());
            }
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn native_links_allow_ambient_non_regular_targets() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    std::fs::create_dir(&destination).unwrap();
    let _socket = UnixListener::bind(destination.join("socket")).unwrap();
    let bytes = single_pax_member("link", b'2', b"", "socket", 0o644);
    TarArchive::new(bytes.as_slice())
        .extract_in(
            &destination,
            ExtractPolicy::default().link_policy(LinkPolicy::default().allow_ambient_targets(true)),
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("link")).unwrap(),
        Path::new("socket")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn ambient_link_components_must_resolve_beneath_the_root() {
    use support::symlink_dir;

    let temp = tempdir().unwrap();
    let policy =
        ExtractPolicy::default().link_policy(LinkPolicy::default().allow_ambient_targets(true));

    let destination = temp.path().join("contained-leaf");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("target"), b"inside").unwrap();
    symlink_file(Path::new("target"), destination.join("ambient-link")).unwrap();
    let bytes = single_pax_member("alias", b'2', b"", "ambient-link", 0o644);
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("alias")).unwrap(),
        Path::new("ambient-link")
    );

    let destination = temp.path().join("contained-intermediate");
    std::fs::create_dir_all(destination.join("target")).unwrap();
    std::fs::write(destination.join("target/file"), b"inside").unwrap();
    symlink_dir(Path::new("target"), destination.join("ambient-link")).unwrap();
    let bytes = single_pax_member("alias", b'2', b"", "ambient-link/file", 0o644);
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, policy)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("alias")).unwrap(),
        Path::new("ambient-link/file")
    );

    let destination = temp.path().join("leaf");
    let outside = temp.path().join("outside-file");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(&outside, b"outside").unwrap();
    symlink_file(&outside, destination.join("ambient-link")).unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("safe", b'0', b"safe", "", 0o644)
        .pax(b'x', &pax_record(PaxKeyword::LinkPath, "ambient-link"))
        .ustar("alias", b'2', b"", "safe", 0o644);
    let bytes = archive.finish();
    assert!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, policy)
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
    let bytes = single_pax_member("alias", b'2', b"", "ambient-link/file", 0o644);
    assert!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, policy)
            .await
            .is_err()
    );
    assert!(!destination.join("alias").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn default_target_policy_uses_filesystem_provenance() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("declared-ambient-directory");
    std::fs::create_dir_all(destination.join("ambient")).unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("ambient", b'5', b"", "", 0o755)
        .ustar("alias", b'2', b"", "ambient", 0o644);
    let bytes = archive.finish();
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::InvalidLink {
            reason: "ambient target is not allowed",
            ..
        })
    ));

    let destination = temp.path().join("created-file-under-ambient-directory");
    std::fs::create_dir_all(destination.join("ambient")).unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("ambient/file", b'0', b"archive", "", 0o644)
        .ustar("alias", b'2', b"", "ambient/file", 0o644);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_link(destination.join("alias")).unwrap(),
        Path::new("ambient/file")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_graphs_allow_finite_expansion_and_reject_cycles_and_escapes() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("finite");
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("file", b'0', b"ok", "", 0o644)
        .ustar("a", b'2', b"", "file", 0o644)
        .ustar("b", b'2', b"", "a", 0o644);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("b")).unwrap(),
        "ok"
    );
    assert_eq!(
        std::fs::read_link(destination.join("a")).unwrap(),
        Path::new("file")
    );
    assert_eq!(
        std::fs::read_link(destination.join("b")).unwrap(),
        Path::new("a")
    );

    for (case, first_target, second_target, expansion_limit) in [
        ("cycle", "b", "a", false),
        ("growing-cycle", "b/x", "a/y", true),
    ] {
        let destination = temp.path().join(case);
        let mut archive = ArchiveBuilder::new();
        archive.ustar("a", b'2', b"", first_target, 0o644).ustar(
            "b",
            b'2',
            b"",
            second_target,
            0o644,
        );
        let bytes = archive.finish();
        let error = TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await
            .unwrap_err();
        assert!(matches!(error, ExtractError::InvalidLink { .. }));
        if expansion_limit {
            assert!(matches!(
                error,
                ExtractError::InvalidLink {
                    reason: "symbolic-link target expansion limit exceeded",
                    ..
                }
            ));
        }
        assert!(!destination.join("a").exists());
        assert!(!destination.join("b").exists());
    }

    let destination = temp.path().join("growing-cycle-work-limit");
    let suffix = "x".repeat(512);
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(
            b'x',
            &pax_record(PaxKeyword::LinkPath, &format!("b/{suffix}")),
        )
        .ustar("a", b'2', b"", "fallback", 0o644)
        .pax(
            b'x',
            &pax_record(PaxKeyword::LinkPath, &format!("a/{suffix}")),
        )
        .ustar("b", b'2', b"", "fallback", 0o644);
    let bytes = archive.finish();
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::InvalidLink {
            reason: "symbolic-link target resolution work limit exceeded",
            ..
        })
    ));
    assert!(!destination.join("a").exists());
    assert!(!destination.join("b").exists());

    let destination = temp.path().join("escape");
    let bytes = single_pax_member("link", b'2', b"", "../outside", 0o644);
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::UnsafePath { .. })
    ));
    assert!(!destination.join("link").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn overwritten_pending_symlinks_do_not_affect_installation_or_resolution() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("obsolete", b'2', b"", "missing", 0o644)
        .ustar("obsolete", b'0', b"file", "", 0o644)
        .ustar("alias", b'2', b"", "target", 0o644)
        .ustar("target", b'2', b"", "missing", 0o644)
        .ustar("target", b'0', b"target", "", 0o644);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(destination.join("obsolete")).unwrap(),
        b"file"
    );
    assert_eq!(std::fs::read(destination.join("alias")).unwrap(), b"target");
    assert_eq!(
        std::fs::read_link(destination.join("alias")).unwrap(),
        Path::new("target")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn later_link_entries_replace_links_of_the_same_kind() {
    let temp = tempdir().unwrap();
    for (case, typeflag) in [("symbolic-link", b'2'), ("hard-link", b'1')] {
        let destination = temp.path().join(case);
        let mut archive = ArchiveBuilder::new();
        archive
            .ustar("first", b'0', b"first", "", 0o644)
            .ustar("second", b'0', b"second", "", 0o644)
            .ustar("same", typeflag, b"", "first", 0o644)
            .ustar("same", typeflag, b"", "second", 0o644);
        let bytes = archive.finish();
        TarArchive::new(bytes.as_slice())
            .extract_in(
                &destination,
                ExtractPolicy::default().link_policy(LinkPolicy::default().allow_hard_links(true)),
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read(destination.join("same")).unwrap(), b"second");
        if typeflag == b'2' {
            assert_eq!(
                std::fs::read_link(destination.join("same")).unwrap(),
                Path::new("second")
            );
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn case_folded_deferred_symlinks_honor_overwrite_policy() {
    let temp = tempdir().expect("temporary directory should be created");
    let case_probe = temp.path().join("case-fold-probe-a");
    std::fs::write(&case_probe, b"").expect("case-fold probe should be created");
    let case_insensitive = temp.path().join("case-fold-probe-A").exists();
    std::fs::remove_file(case_probe).expect("case-fold probe should be removed");
    if !case_insensitive {
        return;
    }

    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("first", b'0', b"first", "", 0o644)
        .ustar("second", b'0', b"second", "", 0o644)
        .ustar("2621A", b'2', b"", "first", 0o644)
        .ustar("2621a", b'2', b"", "second", 0o644);
    let bytes = archive.finish();

    let destination = temp.path().join("overwrites");
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("later case-folded link should replace the earlier link");
    assert_eq!(
        std::fs::read_link(destination.join("2621A"))
            .expect("case-folded symbolic link should be readable"),
        Path::new("second")
    );
    assert_eq!(
        std::fs::read(destination.join("2621a"))
            .expect("case-folded symbolic link target should be readable"),
        b"second"
    );

    let destination = temp.path().join("no-overwrites");
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(
                &destination,
                ExtractPolicy::default().allow_overwrites(false),
            )
            .await,
        Err(ExtractError::PathCollision { path }) if path == Path::new("2621a")
    ));
    assert_eq!(
        std::fs::read_link(destination.join("2621A"))
            .expect("first symbolic link should remain after the collision"),
        Path::new("first")
    );

    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("first", b'0', b"first", "", 0o644)
        .ustar("file-A", b'2', b"", "first", 0o644)
        .ustar("file-a", b'0', b"later", "", 0o644)
        .ustar("directory-A", b'2', b"", "first", 0o644)
        .ustar("directory-a", b'5', b"", "", 0o755);
    let bytes = archive.finish();

    let destination = temp.path().join("later-non-links");
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("later non-link aliases should retain precedence");
    assert_eq!(
        std::fs::read(destination.join("file-A"))
            .expect("later case-folded file should be readable"),
        b"later"
    );
    assert!(destination.join("directory-A").is_dir());

    let destination = temp.path().join("no-cross-kind-overwrites");
    assert!(matches!(
        TarArchive::new(bytes.as_slice())
            .extract_in(
                &destination,
                ExtractPolicy::default().allow_overwrites(false),
            )
            .await,
        Err(ExtractError::PathCollision { path }) if path == Path::new("file-A")
    ));
    assert_eq!(
        std::fs::read(destination.join("file-a"))
            .expect("later file should remain after the collision"),
        b"later"
    );
}

#[tokio::test]
async fn hard_links_require_prior_archive_targets_and_apply_linkdata() {
    let temp = tempdir().unwrap();
    let policy = ExtractPolicy::default().link_policy(LinkPolicy::default().allow_hard_links(true));
    let destination = temp.path().join("linkdata");
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("a", b'0', b"old", "", 0o644)
        .ustar("b", b'1', b"new", "a", 0o644);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, policy)
        .await
        .unwrap();
    assert_eq!(std::fs::read(destination.join("a")).unwrap(), b"new");
    assert_eq!(std::fs::read(destination.join("b")).unwrap(), b"new");

    let unresolved = single_pax_member("b", b'1', b"", "a", 0o644);
    assert!(matches!(
        TarArchive::new(unresolved.as_slice())
            .extract_in(temp.path().join("forward"), policy)
            .await,
        Err(ExtractError::InvalidLink { .. })
    ));

    let destination = temp.path().join("ambient");
    std::fs::create_dir(&destination).unwrap();
    std::fs::write(destination.join("a"), b"ambient").unwrap();
    assert!(matches!(
        TarArchive::new(unresolved.as_slice())
            .extract_in(&destination, policy)
            .await,
        Err(ExtractError::InvalidLink { .. })
    ));
    assert_eq!(std::fs::read(destination.join("a")).unwrap(), b"ambient");
    assert!(!destination.join("b").exists());

    let destination = temp.path().join("different-mode");
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("a", b'0', b"", "", 0o644)
        .ustar("b", b'1', b"", "a", 0o755);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, policy)
        .await
        .unwrap();
    assert!(destination.join("b").is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let destination = temp.path().join("linkdata-mode");
        let mut archive = ArchiveBuilder::new();
        archive
            .ustar("a", b'0', b"old", "", 0o644)
            .ustar("b", b'1', b"new", "a", 0o755);
        let bytes = archive.finish();
        TarArchive::new(bytes.as_slice())
            .extract_in(&destination, policy)
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
            .ustar("target", b'0', b"keep", "", 0o644)
            .ustar(path, b'1', b"", "target", 0o644);
        let bytes = archive.finish();
        assert!(matches!(
            TarArchive::new(bytes.as_slice())
                .extract_in(
                    &destination,
                    ExtractPolicy::default()
                        .link_policy(LinkPolicy::default().allow_hard_links(true)),
                )
                .await,
            Err(ExtractError::InvalidLink { .. })
        ));
        assert_eq!(std::fs::read(destination.join("target")).unwrap(), b"keep");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn native_symlink_and_hard_link_builders_compose() {
    let temp = tempdir().unwrap();
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("target", b'0', b"contents", "", 0o644)
        .ustar("symbolic", b'2', b"", "target", 0o644)
        .ustar("hard", b'1', b"", "target", 0o644);
    let bytes = archive.finish();
    TarArchive::new(bytes.as_slice())
        .extract_in(
            temp.path(),
            ExtractPolicy::default().link_policy(LinkPolicy::default().allow_hard_links(true)),
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
