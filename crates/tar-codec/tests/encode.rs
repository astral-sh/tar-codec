pub mod support;

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tar_codec::{
    decode::{Archive, DecodeError, DecodePolicy},
    default_name_validator,
    encode::{EncodeError, EncodePolicy, Encoder, EntryMetadata, TraversalError},
};
use tar_framing::{
    UstarKind,
    logical::{MemberExtensions, TarReader},
    write::FramingWriteError,
};
use tempfile::tempdir;
use tokio::io::AsyncWrite;

#[derive(Default)]
struct FailingWriter;

impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("injected write failure")))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn encoded_paths(bytes: &[u8]) -> Vec<String> {
    let mut reader = TarReader::new(bytes);
    let mut paths = Vec::new();
    while let Some(member) = reader.next_frame().await.unwrap() {
        paths.push(String::from_utf8(member.effective_path().unwrap().into_owned()).unwrap());
        member.payload.skip().await.unwrap();
    }
    paths
}

#[tokio::test]
async fn manual_entries_round_trip_and_preserve_archive_names() {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .add_entry(
            "bin/tool",
            b"run",
            EntryMetadata::default().executable(true),
        )
        .await
        .unwrap();
    encoder
        .add_entry("README", b"hello", EntryMetadata::default())
        .await
        .unwrap();
    let bytes = encoder.finish().await.unwrap();

    assert_eq!(encoded_paths(&bytes).await, ["bin/tool", "README"]);
    let mut reader = TarReader::new(bytes.as_slice());
    while let Some(member) = reader.next_frame().await.unwrap() {
        assert!(matches!(&member.extensions, MemberExtensions::Pax(_)));
        member.payload.skip().await.unwrap();
    }
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(std::fs::read(destination.join("bin/tool")).unwrap(), b"run");
    assert_eq!(std::fs::read(destination.join("README")).unwrap(), b"hello");
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
        assert_eq!(
            std::fs::metadata(destination.join("README"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }

    let mut encoder = Encoder::new(Vec::new());
    for path in ["/absolute", "C:/ambiguous", "nested/../name", r"back\slash"] {
        encoder
            .add_entry(path, b"", EntryMetadata::default())
            .await
            .unwrap();
    }
    let bytes = encoder.finish().await.unwrap();
    assert_eq!(
        encoded_paths(&bytes).await,
        ["/absolute", "C:/ambiguous", "nested/../name", r"back\slash",]
    );
}

#[tokio::test]
async fn manual_regular_entry_rejects_trailing_separator_before_writing() {
    let mut encoder = Encoder::new(Vec::new());
    assert!(matches!(
        encoder
            .add_entry("file/", b"rejected", EntryMetadata::default())
            .await,
        Err(EncodeError::Framing(
            FramingWriteError::TrailingPathSeparator {
                kind: UstarKind::Regular
            }
        ))
    ));

    encoder
        .add_entry("accepted", b"contents", EntryMetadata::default())
        .await
        .unwrap();
    let bytes = encoder.finish().await.unwrap();
    assert_eq!(encoded_paths(&bytes).await, ["accepted"]);
}

#[tokio::test]
async fn manual_validation_and_collision_errors_leave_the_encoder_usable() {
    let mut encoder = Encoder::new(Vec::new());
    assert!(matches!(
        encoder
            .add_entry(" leading", b"", EntryMetadata::default())
            .await,
        Err(EncodeError::NameRejected {
            context: "member path",
            ..
        })
    ));
    encoder
        .add_entry("allowed", b"ok", EntryMetadata::default())
        .await
        .unwrap();
    encoder
        .add_entry("dir/file", b"first", EntryMetadata::default())
        .await
        .unwrap();
    for path in ["dir/file", "dir/file/child"] {
        assert!(matches!(
            encoder.add_entry(path, b"", EntryMetadata::default()).await,
            Err(EncodeError::PathCollision { .. })
        ));
    }
    encoder
        .add_entry("dir/other", b"other", EntryMetadata::default())
        .await
        .unwrap();
    let bytes = encoder.finish().await.unwrap();
    assert_eq!(
        encoded_paths(&bytes).await,
        ["allowed", "dir/file", "dir/other"]
    );

    let policy = EncodePolicy::default().name_validator(Some(|name| {
        default_name_validator(name) && !name.contains("blocked")
    }));
    let mut encoder = Encoder::with_policy(Vec::new(), policy);
    assert!(matches!(
        encoder
            .add_entry("blocked", b"", EntryMetadata::default())
            .await,
        Err(EncodeError::NameRejected { value, .. }) if value == "blocked"
    ));

    let policy = EncodePolicy::default().name_validator(None);
    let mut encoder = Encoder::with_policy(Vec::new(), policy);
    encoder
        .add_entry(" leading", b"", EntryMetadata::default())
        .await
        .unwrap();
    encoder.finish().await.unwrap();
}

#[tokio::test]
async fn write_failures_and_late_collisions_poison_the_encoder() {
    let mut encoder = Encoder::new(FailingWriter);
    assert!(matches!(
        encoder
            .add_entry("file", b"contents", EntryMetadata::default())
            .await,
        Err(EncodeError::Write { .. })
    ));
    assert!(matches!(
        encoder
            .add_entry("other", b"", EntryMetadata::default())
            .await,
        Err(EncodeError::Poisoned)
    ));

    let temp = tempdir().unwrap();
    let source = temp.path().join("tree");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("file"), "new").unwrap();
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .add_entry("tree/file", b"existing", EntryMetadata::default())
        .await
        .unwrap();
    assert!(matches!(
        encoder.add_directory(&source).await,
        Err(EncodeError::PathCollision { .. })
    ));
    assert!(matches!(
        encoder
            .add_entry("other", b"", EntryMetadata::default())
            .await,
        Err(EncodeError::Poisoned)
    ));
}

#[tokio::test]
async fn recursive_encoding_is_sorted_and_round_trips_small_and_large_files() {
    const LARGE_FILE_BYTES: usize = 1024 * 1024 + 17;

    let temp = tempdir().unwrap();
    let source = temp.path().join("tree");
    std::fs::create_dir_all(source.join("sub")).unwrap();
    std::fs::write(source.join("z"), "last").unwrap();
    std::fs::write(source.join("a"), "first").unwrap();
    std::fs::write(source.join("sub/file"), "nested").unwrap();
    std::fs::write(source.join("sub/large"), vec![b'x'; LARGE_FILE_BYTES]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(source.join("a"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut encoder = Encoder::new(Vec::new());
    encoder.add_directory(&source).await.unwrap();
    let bytes = encoder.finish().await.unwrap();
    assert_eq!(
        encoded_paths(&bytes).await,
        [
            "tree",
            "tree/a",
            "tree/sub",
            "tree/sub/file",
            "tree/sub/large",
            "tree/z",
        ]
    );

    let destination = temp.path().join("out");
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("tree/sub/file")).unwrap(),
        "nested"
    );
    assert_eq!(
        std::fs::metadata(destination.join("tree/sub/large"))
            .unwrap()
            .len(),
        LARGE_FILE_BYTES as u64
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_ne!(
            std::fs::metadata(destination.join("tree/a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn recursive_encoding_preserves_symlinks_and_repeated_inodes() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().unwrap();
    let source = temp.path().join("safe");
    std::fs::create_dir_all(source.join("sub")).unwrap();
    std::fs::write(source.join("sub/file"), "contents").unwrap();
    std::fs::hard_link(source.join("sub/file"), source.join("copy")).unwrap();
    symlink("sub", source.join("directory")).unwrap();
    symlink("directory/file", source.join("file")).unwrap();

    let mut encoder = Encoder::new(Vec::new());
    encoder.add_directory(&source).await.unwrap();
    let bytes = encoder.finish().await.unwrap();

    let mut reader = TarReader::new(bytes.as_slice());
    let mut regular_files = 0;
    while let Some(member) = reader.next_frame().await.unwrap() {
        if member.header.kind == UstarKind::Regular {
            regular_files += 1;
        }
        member.payload.skip().await.unwrap();
    }
    assert_eq!(regular_files, 2);

    let destination = temp.path().join("out");
    Archive::new(bytes.as_slice())
        .extract(&destination, DecodePolicy::default())
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(destination.join("safe/file")).unwrap(),
        "contents"
    );

    let escape = temp.path().join("escape");
    std::fs::create_dir(&escape).unwrap();
    symlink("../../outside", escape.join("link")).unwrap();
    let mut encoder = Encoder::new(Vec::new());
    encoder.add_directory(&escape).await.unwrap();
    let bytes = encoder.finish().await.unwrap();
    assert!(matches!(
        Archive::new(bytes.as_slice())
            .extract(temp.path().join("escape-out"), DecodePolicy::default())
            .await,
        Err(DecodeError::UnsafePath {
            context: "symbolic-link target",
            ..
        })
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn recursive_source_and_validation_errors_are_reported_publicly() {
    use std::{
        ffi::OsString,
        os::unix::{ffi::OsStringExt, fs::symlink},
    };

    let temp = tempdir().unwrap();
    let target = temp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let linked_root = temp.path().join("linked-root");
    symlink(&target, &linked_root).unwrap();
    let mut encoder = Encoder::new(Vec::new());
    assert!(matches!(
        encoder.add_directory(&linked_root).await,
        Err(EncodeError::Traversal(
            TraversalError::SourceNotDirectory { .. }
        ))
    ));

    let rejected_root = temp.path().join(" rejected");
    std::fs::create_dir(&rejected_root).unwrap();
    let mut encoder = Encoder::new(Vec::new());
    assert!(matches!(
        encoder.add_directory(&rejected_root).await,
        Err(EncodeError::Traversal(TraversalError::NameRejected {
            context: "member path",
            ..
        }))
    ));

    let custom_source = temp.path().join("custom-link");
    std::fs::create_dir(&custom_source).unwrap();
    symlink("blocked", custom_source.join("link")).unwrap();
    let policy = EncodePolicy::default().name_validator(Some(|name| {
        default_name_validator(name) && !name.contains("blocked")
    }));
    let mut encoder = Encoder::with_policy(Vec::new(), policy);
    assert!(matches!(
        encoder.add_directory(&custom_source).await,
        Err(EncodeError::Traversal(TraversalError::NameRejected {
            context: "symbolic-link target",
            value,
        })) if value == "blocked"
    ));

    let disabled_source = temp.path().join("disabled-link");
    std::fs::create_dir(&disabled_source).unwrap();
    symlink(" rejected", disabled_source.join("link")).unwrap();
    let mut encoder =
        Encoder::with_policy(Vec::new(), EncodePolicy::default().name_validator(None));
    encoder.add_directory(&disabled_source).await.unwrap();
    encoder.finish().await.unwrap();

    let non_utf8_source = temp.path().join("non-utf8");
    std::fs::create_dir(&non_utf8_source).unwrap();
    let invalid = OsString::from_vec(vec![0xff]);
    if std::fs::write(non_utf8_source.join(&invalid), "contents").is_ok() {
        let mut encoder = Encoder::new(Vec::new());
        assert!(matches!(
            encoder.add_directory(&non_utf8_source).await,
            Err(EncodeError::Traversal(
                TraversalError::NonUtf8SourcePath { .. }
            ))
        ));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn recursive_encoding_rejects_unsupported_filesystem_types() {
    use std::os::unix::net::UnixListener;

    let temp = tempdir().unwrap();
    let source = temp.path().join("socket");
    std::fs::create_dir(&source).unwrap();
    let _listener = UnixListener::bind(source.join("listener")).unwrap();
    let mut encoder = Encoder::new(Vec::new());
    assert!(matches!(
        encoder.add_directory(&source).await,
        Err(EncodeError::Traversal(
            TraversalError::UnsupportedFilesystemType { .. }
        ))
    ));
    encoder
        .add_entry("other", b"ok", EntryMetadata::default())
        .await
        .unwrap();
    encoder.finish().await.unwrap();
}
