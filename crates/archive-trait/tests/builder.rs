use std::{io::Write as _, path::PathBuf};

#[cfg(unix)]
use archive_trait::builder::SymlinkPolicy;
use archive_trait::{
    ArchiveBuilder, BuildError, BuilderState, EntryMetadata, EntryPayload, TraversalError,
    builder::BuilderPolicy, default_name_validator,
};
use tempfile::tempdir;
use thiserror::Error;

const LARGE_FILE_BYTES: usize = 1024 * 1024 + 17;

#[derive(Debug, Eq, PartialEq)]
enum RecordedEntry {
    File {
        path: String,
        data: Vec<u8>,
        executable: bool,
        chunks: usize,
    },
    Directory(String),
    SymbolicLink {
        path: String,
        target: String,
    },
}

impl RecordedEntry {
    fn file(path: &str, data: &[u8], executable: bool) -> Self {
        Self::File {
            path: path.to_owned(),
            data: data.to_vec(),
            executable,
            chunks: 1,
        }
    }
}

#[derive(Debug, Error)]
#[error("injected format failure")]
struct MockError;

enum SourceMutation {
    Grow(PathBuf),
    Truncate(PathBuf),
}

struct MockBuilder {
    state: BuilderState,
    entries: Vec<RecordedEntry>,
    fail_path: Option<String>,
    source_mutation: Option<SourceMutation>,
}

impl MockBuilder {
    fn new() -> Self {
        Self::with_policy(BuilderPolicy::default())
    }

    fn with_policy(policy: BuilderPolicy) -> Self {
        Self {
            state: BuilderState::new(policy),
            entries: Vec::new(),
            fail_path: None,
            source_mutation: None,
        }
    }

    fn mutate_source(&mut self) {
        let result = match self.source_mutation.take() {
            Some(SourceMutation::Grow(path)) => std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .and_then(|mut file| file.write_all(b"growth")),
            Some(SourceMutation::Truncate(path)) => std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .map(drop),
            None => return,
        };
        assert!(result.is_ok(), "source mutation should succeed: {result:?}");
    }
}

impl ArchiveBuilder for MockBuilder {
    type Error = MockError;

    fn builder_state(&mut self) -> &mut BuilderState {
        &mut self.state
    }

    async fn finish_archive(&mut self) -> Result<(), BuildError<Self::Error>> {
        Ok(())
    }

    async fn write_file_member(
        &mut self,
        path: &str,
        payload: &mut EntryPayload<'_>,
        metadata: EntryMetadata,
    ) -> Result<(), BuildError<Self::Error>> {
        if self.fail_path.as_deref() == Some(path) {
            self.state.poison();
            return Err(BuildError::Encoder(MockError));
        }
        self.mutate_source();
        let mut data = Vec::new();
        let mut chunks = 0;
        loop {
            match payload.next_chunk().await {
                Ok(Some(chunk)) => {
                    chunks += 1;
                    data.extend_from_slice(chunk);
                }
                Ok(None) => break,
                Err(error) => {
                    self.state.poison();
                    return Err(error);
                }
            }
        }
        self.entries.push(RecordedEntry::File {
            path: path.to_owned(),
            data,
            executable: metadata.is_executable(),
            chunks,
        });
        Ok(())
    }

    async fn write_directory_member(&mut self, path: &str) -> Result<(), BuildError<Self::Error>> {
        if self.fail_path.as_deref() == Some(path) {
            self.state.poison();
            return Err(BuildError::Encoder(MockError));
        }
        self.entries.push(RecordedEntry::Directory(path.to_owned()));
        Ok(())
    }

    async fn write_symbolic_link_member(
        &mut self,
        path: &str,
        target: &str,
    ) -> Result<(), BuildError<Self::Error>> {
        self.entries.push(RecordedEntry::SymbolicLink {
            path: path.to_owned(),
            target: target.to_owned(),
        });
        Ok(())
    }
}

#[tokio::test]
async fn manual_entries_preserve_order_metadata_and_collision_state() {
    let mut builder = MockBuilder::new();
    builder
        .add_entry(
            "bin/tool",
            b"run",
            EntryMetadata::default().executable(true),
        )
        .await
        .expect("first entry should be added");
    builder
        .add_entry("README", b"hello", EntryMetadata::default())
        .await
        .expect("second entry should be added");

    for path in ["bin/tool", "bin/tool/child"] {
        assert!(matches!(
            builder.add_entry(path, b"", EntryMetadata::default()).await,
            Err(BuildError::PathCollision { .. })
        ));
    }
    let temp = tempdir().expect("temporary directory should be created");
    let directory = temp.path().join("bin");
    std::fs::create_dir(&directory).expect("directory should be created");
    builder
        .add_directory(&directory)
        .await
        .expect("an implicit ancestor should accept its explicit directory member");
    builder
        .add_entry("bin/other", b"other", EntryMetadata::default())
        .await
        .expect("preflight failures should leave the builder usable");

    assert_eq!(
        builder.entries,
        [
            RecordedEntry::file("bin/tool", b"run", true),
            RecordedEntry::file("README", b"hello", false),
            RecordedEntry::Directory("bin".to_owned()),
            RecordedEntry::file("bin/other", b"other", false),
        ]
    );
}

#[tokio::test]
async fn name_validation_supports_default_custom_and_disabled_policies() {
    let policies = [
        (
            BuilderPolicy::default(),
            " leading",
            false,
            "default validation should reject boundary whitespace",
        ),
        (
            BuilderPolicy::default().name_validator(Some(|name| {
                default_name_validator(name) && !name.contains("blocked")
            })),
            "blocked",
            false,
            "custom validation should reject matching names",
        ),
        (
            BuilderPolicy::default().name_validator(None),
            " leading",
            true,
            "disabled validation should accept boundary whitespace",
        ),
    ];

    for (policy, path, accepted, context) in policies {
        let mut builder = MockBuilder::with_policy(policy);
        let result = builder.add_entry(path, b"", EntryMetadata::default()).await;
        assert_eq!(result.is_ok(), accepted, "{context}: {result:?}");
        if !accepted {
            builder
                .add_entry("accepted", b"ok", EntryMetadata::default())
                .await
                .expect("name rejection should leave the builder usable");
        }
    }
}

#[tokio::test]
async fn recursive_build_is_sorted_and_streams_small_and_large_files() {
    let temp = tempdir().expect("temporary directory should be created");
    let source = temp.path().join("tree");
    std::fs::create_dir_all(source.join("sub")).expect("source tree should be created");
    std::fs::write(source.join("z"), b"last").expect("z should be written");
    std::fs::write(source.join("a"), b"first").expect("a should be written");
    std::fs::write(source.join("sub/file"), b"nested").expect("small file should be written");
    std::fs::write(source.join("sub/large"), vec![b'x'; LARGE_FILE_BYTES])
        .expect("large file should be written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(source.join("a"), std::fs::Permissions::from_mode(0o755))
            .expect("executable permissions should be set");
    }

    let mut builder = MockBuilder::new();
    builder
        .add_directory(&source)
        .await
        .expect("directory should be added");

    let paths = builder
        .entries
        .iter()
        .map(|entry| match entry {
            RecordedEntry::File { path, .. }
            | RecordedEntry::Directory(path)
            | RecordedEntry::SymbolicLink { path, .. } => path.as_str(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "tree",
            "tree/a",
            "tree/sub",
            "tree/sub/file",
            "tree/sub/large",
            "tree/z",
        ]
    );
    assert!(builder.entries.iter().any(|entry| matches!(
        entry,
        RecordedEntry::File { path, data, chunks, .. }
            if path == "tree/sub/file" && data == b"nested" && *chunks == 1
    )));
    assert!(builder.entries.iter().any(|entry| matches!(
        entry,
        RecordedEntry::File { path, data, chunks, .. }
            if path == "tree/sub/large" && data.len() == LARGE_FILE_BYTES && *chunks == 2
    )));
    #[cfg(unix)]
    assert!(builder.entries.iter().any(|entry| matches!(
        entry,
        RecordedEntry::File { path, executable: true, .. } if path == "tree/a"
    )));
}

#[cfg(unix)]
#[tokio::test]
async fn recursive_build_applies_symlink_policy() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("temporary directory should be created");
    let source = temp.path().join("links");
    std::fs::create_dir(&source).expect("source directory should be created");
    std::fs::write(source.join("target"), b"contents").expect("target should be written");
    symlink("target", source.join("link")).expect("symbolic link should be created");
    let directory_target = temp.path().join("directory-target");
    std::fs::create_dir(&directory_target).expect("directory target should be created");
    symlink("../directory-target", source.join("directory"))
        .expect("directory symbolic link should be created");

    let linked_root = temp.path().join("root-link");
    symlink("links", &linked_root).expect("root symbolic link should be created");
    for rejected_source in [&source, &linked_root] {
        assert!(matches!(
            MockBuilder::new().add_directory(rejected_source).await,
            Err(BuildError::Traversal(
                TraversalError::SymbolicLinkRejected { .. }
            ))
        ));
    }

    let preserve = BuilderPolicy::default().symlink_policy(SymlinkPolicy::Preserve);
    let mut builder = MockBuilder::with_policy(preserve);
    builder
        .add_directory(&source)
        .await
        .expect("directory should be added");

    assert!(builder.entries.contains(&RecordedEntry::SymbolicLink {
        path: "links/link".to_owned(),
        target: "target".to_owned(),
    }));
    assert!(builder.entries.contains(&RecordedEntry::SymbolicLink {
        path: "links/directory".to_owned(),
        target: "../directory-target".to_owned(),
    }));

    symlink("blocked", source.join("custom")).expect("custom link should be created");
    let policy = preserve.name_validator(Some(|name| {
        default_name_validator(name) && !name.contains("blocked")
    }));
    assert!(matches!(
        MockBuilder::with_policy(policy).add_directory(&source).await,
        Err(BuildError::Traversal(TraversalError::NameRejected {
            context: "symbolic-link target",
            value,
        })) if value == "blocked"
    ));

    std::fs::remove_file(source.join("custom")).expect("custom link should be removed");
    symlink(" leading", source.join("disabled")).expect("disabled-policy link should be created");
    MockBuilder::with_policy(preserve.name_validator(None))
        .add_directory(&source)
        .await
        .expect("disabled validation should accept the link target");
}

#[cfg(unix)]
#[tokio::test]
async fn recursive_build_reports_non_utf8_and_unsupported_sources() {
    use std::{
        ffi::OsString,
        os::unix::{ffi::OsStringExt as _, fs::symlink, net::UnixListener},
    };

    let temp = tempdir().expect("temporary directory should be created");
    let source = temp.path().join("file");
    std::fs::write(&source, b"contents").expect("source file should be written");
    assert!(matches!(
        MockBuilder::new().add_directory(&source).await,
        Err(BuildError::Traversal(
            TraversalError::SourceNotDirectory { .. }
        ))
    ));

    let source = temp.path().join(" rejected");
    std::fs::create_dir(&source).expect("rejected source directory should be created");
    assert!(matches!(
        MockBuilder::new().add_directory(&source).await,
        Err(BuildError::Traversal(TraversalError::NameRejected {
            context: "member path",
            ..
        }))
    ));

    let source = temp.path().join("invalid");
    std::fs::create_dir(&source).expect("source directory should be created");
    let invalid_name = OsString::from_vec(vec![0xff]);
    if std::fs::write(source.join(&invalid_name), b"contents").is_ok() {
        assert!(matches!(
            MockBuilder::new().add_directory(&source).await,
            Err(BuildError::Traversal(
                TraversalError::NonUtf8SourcePath { .. }
            ))
        ));
    }

    let source = temp.path().join("invalid-link");
    std::fs::create_dir(&source).expect("link source directory should be created");
    symlink(
        PathBuf::from(OsString::from_vec(vec![0xff])),
        source.join("link"),
    )
    .expect("non-UTF-8 symbolic link should be created");
    assert!(matches!(
        MockBuilder::with_policy(BuilderPolicy::default().symlink_policy(SymlinkPolicy::Preserve))
            .add_directory(&source)
            .await,
        Err(BuildError::Traversal(
            TraversalError::NonUtf8LinkTarget { .. }
        ))
    ));

    let source = temp.path().join("socket");
    std::fs::create_dir(&source).expect("socket directory should be created");
    let _listener =
        UnixListener::bind(source.join("listener")).expect("Unix-domain socket should be created");
    assert!(matches!(
        MockBuilder::new().add_directory(&source).await,
        Err(BuildError::Traversal(
            TraversalError::UnsupportedFilesystemType { .. }
        ))
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn late_traversal_failures_poison_after_a_completed_batch() {
    use std::os::unix::net::UnixListener;

    let temp = tempdir().expect("temporary directory should be created");
    let source = temp.path().join("late");
    std::fs::create_dir(&source).expect("source directory should be created");
    for index in 0..256 {
        std::fs::create_dir(source.join(format!("entry-{index:03}")))
            .expect("batch directory should be created");
    }
    let _listener = UnixListener::bind(source.join("unsupported"))
        .expect("Unix-domain socket should be created");

    let mut builder = MockBuilder::new();
    assert!(matches!(
        builder.add_directory(&source).await,
        Err(BuildError::Traversal(
            TraversalError::UnsupportedFilesystemType { .. }
        ))
    ));
    assert!(!builder.entries.is_empty());
    assert!(matches!(
        builder
            .add_entry("other", b"", EntryMetadata::default())
            .await,
        Err(BuildError::Poisoned)
    ));
}

#[tokio::test]
async fn source_growth_and_truncation_poison_after_member_framing() {
    for mutation in ["growth", "truncation"] {
        let temp = tempdir().expect("temporary directory should be created");
        let source = temp.path().join("tree");
        std::fs::create_dir(&source).expect("source directory should be created");
        let file = source.join("large");
        std::fs::write(&file, vec![b'x'; LARGE_FILE_BYTES]).expect("large file should be written");

        let mut builder = MockBuilder::new();
        builder.source_mutation = Some(match mutation {
            "growth" => SourceMutation::Grow(file),
            _ => SourceMutation::Truncate(file),
        });
        assert!(matches!(
            builder.add_directory(&source).await,
            Err(BuildError::ChangedSourceFile { .. })
        ));
        assert!(matches!(
            builder
                .add_entry("other", b"", EntryMetadata::default())
                .await,
            Err(BuildError::Poisoned)
        ));
    }
}

#[tokio::test]
async fn early_failures_leave_builders_usable_but_late_failures_poison_them() {
    let temp = tempdir().expect("temporary directory should be created");
    let mut builder = MockBuilder::new();
    assert!(matches!(
        builder.add_directory(temp.path().join("missing")).await,
        Err(BuildError::Traversal(TraversalError::Filesystem { .. }))
    ));
    builder
        .add_entry("kept", b"ok", EntryMetadata::default())
        .await
        .expect("early traversal failure should leave the builder usable");

    let source = temp.path().join("tree");
    std::fs::create_dir(&source).expect("source directory should be created");
    std::fs::write(source.join("file"), b"new").expect("source file should be written");
    let mut builder = MockBuilder::new();
    builder
        .add_entry("tree/file", b"existing", EntryMetadata::default())
        .await
        .expect("manual entry should be added");
    assert!(matches!(
        builder.add_directory(&source).await,
        Err(BuildError::PathCollision { .. })
    ));
    assert!(matches!(
        builder
            .add_entry("other", b"", EntryMetadata::default())
            .await,
        Err(BuildError::Poisoned)
    ));

    let mut builder = MockBuilder::new();
    builder.fail_path = Some("failed".to_owned());
    assert!(matches!(
        builder
            .add_entry("failed", b"payload", EntryMetadata::default())
            .await,
        Err(BuildError::Encoder(MockError))
    ));
    assert!(matches!(
        builder
            .add_entry("other", b"", EntryMetadata::default())
            .await,
        Err(BuildError::Poisoned)
    ));
}
