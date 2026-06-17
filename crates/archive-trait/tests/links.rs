pub mod support;

use archive_trait::{
    Archive as _, ExtractError, ExtractPolicy, ExtractPolicyViolation, LinkPolicy, SymlinkPolicy,
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
            entry::symbolic_link("link", "missing"),
            LinkPolicy::default().symlink_policy(SymlinkPolicy::Reject),
            ExtractPolicyViolation::SymbolicLink,
        ),
        (
            "hard",
            "hard",
            entry::hard_link("hard", "missing", b""),
            LinkPolicy::default(),
            ExtractPolicyViolation::HardLink,
        ),
    ] {
        let destination = temp.path().join(case);
        let result = TestArchive::new([member])
            .extract_in(&destination, ExtractPolicy::default().link_policy(policy))
            .await;
        assert!(matches!(
            result,
            Err(ExtractError::PolicyViolation { violation, .. }) if violation == expected
        ));
        assert!(!destination.join(path).exists());
    }

    let destination = temp.path().join("skipped");
    TestArchive::new([entry::symbolic_link("link", "missing")])
        .extract_in(
            &destination,
            ExtractPolicy::default()
                .link_policy(LinkPolicy::default().symlink_policy(SymlinkPolicy::Skip)),
        )
        .await
        .expect("skipped link should not fail");
    assert!(!destination.join("link").exists());
}
