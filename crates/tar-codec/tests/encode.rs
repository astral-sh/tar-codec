pub mod support;

use std::{
    cell::Cell,
    future::Future,
    io,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

#[cfg(unix)]
use tar_codec::builder::{BuilderPolicy, SymlinkPolicy};
use tar_codec::{
    Archive as _, ArchiveBuilder as _, BuildError, EncodeError, EntryMetadata, TarArchive,
    TarEncoder, extract::ExtractPolicy,
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

struct PendingOnceWriter {
    written: Rc<Cell<usize>>,
    wrote_prefix: bool,
    returned_pending: bool,
}

impl AsyncWrite for PendingOnceWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.wrote_prefix {
            let len = buffer.len().min(17);
            self.written.set(self.written.get() + len);
            self.wrote_prefix = true;
            return Poll::Ready(Ok(len));
        }
        if !self.returned_pending {
            self.returned_pending = true;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.written.set(self.written.get() + buffer.len());
        Poll::Ready(Ok(buffer.len()))
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
    while let Some(member) = reader
        .next_frame()
        .await
        .expect("encoded archive should be readable")
    {
        paths.push(
            String::from_utf8(
                member
                    .effective_path()
                    .expect("encoded path should be valid")
                    .into_owned(),
            )
            .expect("encoded path should be UTF-8"),
        );
        member
            .payload
            .skip()
            .await
            .expect("encoded payload should be valid");
    }
    paths
}

#[tokio::test]
async fn manual_entries_are_pax_framed_padded_terminated_and_extractable() {
    let mut bytes = Vec::new();
    let mut encoder = TarEncoder::new(&mut bytes).builder();
    encoder
        .add_entry(
            "bin/tool",
            b"run",
            EntryMetadata::default().executable(true),
        )
        .await
        .expect("executable entry should be added");
    encoder
        .add_entry("README", b"hello", EntryMetadata::default())
        .await
        .expect("readme entry should be added");
    encoder.finish().await.expect("archive should finish");

    assert_eq!(bytes.len() % 512, 0);
    assert!(bytes.ends_with(&[0; 1024]));
    assert_eq!(encoded_paths(&bytes).await, ["bin/tool", "README"]);
    let mut reader = TarReader::new(bytes.as_slice());
    while let Some(member) = reader
        .next_frame()
        .await
        .expect("encoded archive should be readable")
    {
        assert!(matches!(&member.extensions, MemberExtensions::Pax(_)));
        member
            .payload
            .skip()
            .await
            .expect("encoded payload should be valid");
    }

    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("archive should extract");
    assert_eq!(
        std::fs::read(destination.join("bin/tool")).expect("tool should be readable"),
        b"run"
    );
    assert_eq!(
        std::fs::read(destination.join("README")).expect("readme should be readable"),
        b"hello"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

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
async fn tar_path_suffix_rejections_happen_before_output() {
    let mut bytes = Vec::new();
    let mut encoder = TarEncoder::new(&mut bytes).builder();
    for path in [
        ".",
        "..",
        "file/",
        "file/.",
        "file//.",
        "file/././.",
        "file/./././",
        "foo/bar/..",
        "foo/bar/../",
    ] {
        assert!(matches!(
            encoder
                .add_entry(path, b"rejected", EntryMetadata::default())
                .await,
            Err(BuildError::Encoder(EncodeError::Framing(
                FramingWriteError::DirectoryRequiredPathSuffix {
                    kind: UstarKind::Regular
                }
            )))
        ));
    }

    encoder
        .add_entry("accepted", b"contents", EntryMetadata::default())
        .await
        .expect("framing preflight failures should leave the encoder usable");
    encoder.finish().await.expect("archive should finish");
    assert_eq!(encoded_paths(&bytes).await, ["accepted"]);
}

#[tokio::test]
async fn output_failures_poison_the_encoder() {
    let mut encoder = TarEncoder::new(FailingWriter).builder();
    assert!(matches!(
        encoder
            .add_entry("file", b"contents", EntryMetadata::default())
            .await,
        Err(BuildError::Encoder(EncodeError::Write { .. }))
    ));
    assert!(matches!(
        encoder
            .add_entry("other", b"", EntryMetadata::default())
            .await,
        Err(BuildError::Poisoned)
    ));
    assert!(matches!(encoder.finish().await, Err(BuildError::Poisoned)));
}

#[tokio::test]
async fn cancelled_output_write_poisons_the_encoder() {
    let written = Rc::new(Cell::new(0));
    let writer = PendingOnceWriter {
        written: Rc::clone(&written),
        wrote_prefix: false,
        returned_pending: false,
    };
    let mut encoder = TarEncoder::new(writer).builder();
    {
        let mut addition =
            std::pin::pin!(encoder.add_entry("cancelled", b"contents", EntryMetadata::default(),));
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            addition.as_mut().poll(&mut context),
            Poll::Pending
        ));
    }
    assert_eq!(written.get(), 17);

    assert!(matches!(
        encoder
            .add_entry("other", b"contents", EntryMetadata::default())
            .await,
        Err(BuildError::Poisoned)
    ));
    assert!(matches!(encoder.finish().await, Err(BuildError::Poisoned)));
}

#[tokio::test]
async fn recursive_encoding_round_trips_small_and_large_files() {
    const LARGE_FILE_BYTES: usize = 1024 * 1024 + 17;

    let temp = tempdir().expect("temporary directory should be created");
    let source = temp.path().join("tree");
    std::fs::create_dir_all(source.join("sub")).expect("source tree should be created");
    std::fs::write(source.join("small"), b"small").expect("small file should be written");
    std::fs::write(source.join("sub/large"), vec![b'x'; LARGE_FILE_BYTES])
        .expect("large file should be written");

    let mut bytes = Vec::new();
    let mut encoder = TarEncoder::new(&mut bytes).builder();
    encoder
        .add_directory(&source)
        .await
        .expect("directory should be added");
    encoder.finish().await.expect("archive should finish");
    assert_eq!(
        encoded_paths(&bytes).await,
        ["tree", "tree/small", "tree/sub", "tree/sub/large"]
    );

    let destination = temp.path().join("out");
    TarArchive::new(bytes.as_slice())
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("archive should extract");
    assert_eq!(
        std::fs::read(destination.join("tree/small")).expect("small file should be readable"),
        b"small"
    );
    assert_eq!(
        std::fs::metadata(destination.join("tree/sub/large"))
            .expect("large file metadata should be readable")
            .len(),
        LARGE_FILE_BYTES as u64
    );
}

#[cfg(unix)]
#[tokio::test]
async fn recursive_encoding_frames_preserved_symlinks() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("temporary directory should be created");
    let source = temp.path().join("links");
    std::fs::create_dir(&source).expect("source directory should be created");
    std::fs::write(source.join("target"), b"contents").expect("target should be written");
    symlink("target", source.join("link")).expect("symbolic link should be created");

    let policy = BuilderPolicy::default().symlink_policy(SymlinkPolicy::Preserve);
    let mut bytes = Vec::new();
    let mut encoder = TarEncoder::new(&mut bytes).builder_with_policy(policy);
    encoder
        .add_directory(&source)
        .await
        .expect("directory should be added");
    encoder.finish().await.expect("archive should finish");

    let mut reader = TarReader::new(bytes.as_slice());
    let mut link = None;
    while let Some(member) = reader
        .next_frame()
        .await
        .expect("encoded archive should be readable")
    {
        if member.header.kind == UstarKind::SymbolicLink {
            link = Some(
                member
                    .effective_link_path()
                    .expect("link target should be valid")
                    .into_owned(),
            );
        }
        member
            .payload
            .skip()
            .await
            .expect("encoded payload should be valid");
    }
    assert_eq!(link.as_deref(), Some(&b"target"[..]));
}
