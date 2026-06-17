pub mod support;

use archive_trait::{
    Archive as _, ExtractError, ExtractPolicy, ExtractPolicyViolation, LinkPolicy, SymlinkPolicy,
};
use support::{Entry, TestArchive};
use tempfile::tempdir;

#[cfg(unix)]
#[tokio::test]
async fn preserves_symlink_chains_and_supports_hard_link_payloads() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");
    let archive = TestArchive::new([
        Entry::file("target", b"old"),
        Entry::symbolic_link("second", "target"),
        Entry::symbolic_link("first", "second"),
        Entry::hard_link("hard", "target", b"new"),
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
    let destination = temp.path().join("rejected");
    assert!(matches!(
        TestArchive::new([
            Entry::file("target", b"keep"),
            Entry::symbolic_link("link", "target"),
        ])
        .extract_in(
            &destination,
            ExtractPolicy::default()
                .link_policy(LinkPolicy::default().symlink_policy(SymlinkPolicy::Reject),),
        )
        .await,
        Err(ExtractError::PolicyViolation {
            violation: ExtractPolicyViolation::SymbolicLink,
            ..
        })
    ));
    assert!(!destination.join("link").exists());

    let destination = temp.path().join("skipped");
    TestArchive::new([Entry::symbolic_link("link", "missing")])
        .extract_in(
            &destination,
            ExtractPolicy::default()
                .link_policy(LinkPolicy::default().symlink_policy(SymlinkPolicy::Skip)),
        )
        .await
        .expect("skipped link should not fail");
    assert!(!destination.join("link").exists());

    assert!(matches!(
        TestArchive::new([Entry::hard_link("hard", "missing", b"")])
            .extract_in(temp.path().join("hard"), ExtractPolicy::default())
            .await,
        Err(ExtractError::PolicyViolation {
            violation: ExtractPolicyViolation::HardLink,
            ..
        })
    ));
}
