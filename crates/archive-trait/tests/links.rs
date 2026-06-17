pub mod support;

use archive_trait::{
    Archive as _, ExtractError, ExtractPolicyViolation,
    extract::{ExtractPolicy, LinkPolicy, SymlinkPolicy},
};
use support::{TestArchive, entry};
use tempfile::tempdir;

#[cfg(unix)]
#[tokio::test]
async fn preserves_symlink_chains_and_supports_hard_link_payloads() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");
    let archive = TestArchive::new([
        entry::file("target", b"old"),
        entry::symbolic_link("second", "target"),
        entry::symbolic_link("first", "second"),
        entry::hard_link("hard", "target", b"new"),
    ]);
    let policy = ExtractPolicy::default().link_policy(LinkPolicy::default().allow_hard_links(true));

    archive
        .extract_in(&destination, policy)
        .await
        .expect("links should extract");

    for path in ["target", "first", "second", "hard"] {
        assert_eq!(
            std::fs::read(destination.join(path)).expect("link target should be readable"),
            b"new"
        );
    }
}

#[tokio::test]
async fn link_policies_reject_or_skip_without_creating_links() {
    let temp = tempdir().expect("temporary directory should be created");
    for (case, path, member, policy, expected) in [
        (
            "symbolic",
            "link",
            entry::symbolic_link("link", "target"),
            LinkPolicy::default().symlink_policy(SymlinkPolicy::Reject),
            ExtractPolicyViolation::SymbolicLink,
        ),
        (
            "hard",
            "hard",
            entry::hard_link("hard", "target", b"new"),
            LinkPolicy::default(),
            ExtractPolicyViolation::HardLink,
        ),
    ] {
        let destination = temp.path().join(case);
        let result = TestArchive::new([entry::file("target", b"keep"), member])
            .extract_in(&destination, ExtractPolicy::default().link_policy(policy))
            .await;
        assert!(matches!(
            result,
            Err(ExtractError::PolicyViolation { violation, .. }) if violation == expected
        ));
        assert_eq!(
            std::fs::read(destination.join("target")).expect("prior output should remain readable"),
            b"keep"
        );
        assert!(!destination.join(path).exists());
    }

    let destination = temp.path().join("hard-only");
    TestArchive::new([
        entry::file("target", b"old"),
        entry::hard_link("hard", "target", b"new"),
    ])
    .extract_in(
        &destination,
        ExtractPolicy::default().link_policy(
            LinkPolicy::default()
                .symlink_policy(SymlinkPolicy::Reject)
                .allow_hard_links(true),
        ),
    )
    .await
    .expect("hard-link policy should be independent of symbolic links");
    for path in ["target", "hard"] {
        assert_eq!(
            std::fs::read(destination.join(path)).expect("hard link should be readable"),
            b"new"
        );
    }

    let destination = temp.path().join("skipped");
    TestArchive::new([
        entry::file("same", b"keep"),
        entry::symbolic_link("same", "missing"),
        entry::symbolic_link("skipped", "missing"),
    ])
    .extract_in(
        &destination,
        ExtractPolicy::default()
            .link_policy(LinkPolicy::default().symlink_policy(SymlinkPolicy::Skip)),
    )
    .await
    .expect("skipped link should not fail");
    assert_eq!(
        std::fs::read(destination.join("same")).expect("existing file should remain readable"),
        b"keep"
    );
    assert!(!destination.join("skipped").exists());
}
