//! Deterministic high-level encoding for pure pax tar archives.
//!
//! The encoder emits one local pax header before every member. Compression is
//! intentionally left to callers, which may wrap the underlying async writer.
//! Safe non-canonical archive paths are normalized before collision checks and
//! framing.

mod traversal;

pub use self::traversal::TraversalError;

use std::{
    collections::HashMap,
    io::{self, Read},
    mem,
    path::{Path, PathBuf},
};

use tar_framing::{
    MemberKind,
    write::{
        FramingWriteError, PaxMember, end_marker_bytes, frame_pax_member_into, payload_padding,
    },
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use self::traversal::{TraversalEntry, TraversalKind, TraversalStream, stream_directory_entries};
use crate::{
    blocking::with_reusable_buffer,
    paths::{LegalizedPath, NormalizedPath, PathError},
};

const SOURCE_FILE_CHUNK_BYTES: usize = 1024 * 1024;

/// Minimal regular-file metadata accepted by [`Encoder::add_entry`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EntryMetadata {
    executable: bool,
}

impl EntryMetadata {
    /// Configures whether the regular file carries executable intent.
    pub fn executable(mut self, executable: bool) -> Self {
        self.executable = executable;
        self
    }
}

/// A one-pass asynchronous encoder for deterministic pure-pax archives.
pub struct Encoder<W> {
    writer: W,
    sequence: u64,
    entries: HashMap<NormalizedPath, ArchivedEntry>,
    framing_buffer: Vec<u8>,
    poisoned: bool,
}

impl<W> Encoder<W> {
    /// Creates an encoder writing an uncompressed pax archive into `writer`.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            sequence: 0,
            entries: HashMap::new(),
            framing_buffer: Vec::new(),
            poisoned: false,
        }
    }
}

impl<W: AsyncWrite + Unpin> Encoder<W> {
    /// Adds one regular file from an in-memory byte buffer.
    pub async fn add_entry<P, D>(
        &mut self,
        path: P,
        data: D,
        metadata: EntryMetadata,
    ) -> Result<(), EncodeError>
    where
        P: AsRef<Path>,
        D: AsRef<[u8]>,
    {
        self.ensure_active()?;
        let path = normalize_archive_path(path.as_ref())?;
        let implicit_ancestors = preflight_regular_entry(&self.entries, &path)?;
        let data = data.as_ref();
        let size = u64::try_from(data.len())
            .map_err(|_| arithmetic_overflow("manual entry payload size"))?;
        self.write_member(PaxMember {
            path: path.as_str(),
            kind: MemberKind::Regular,
            size,
            link_path: None,
            executable: metadata.executable,
        })
        .await?;
        self.write_bytes(data).await?;
        self.write_padding(size).await?;
        for ancestor in implicit_ancestors {
            self.entries
                .insert(ancestor, ArchivedEntry::Directory { explicit: false });
        }
        self.entries.insert(path, ArchivedEntry::Regular);
        Ok(())
    }

    /// Recursively adds a filesystem directory beneath its UTF-8 basename.
    ///
    /// Entries are visited in deterministic sorted order and files are streamed
    /// with bounded memory. Source symbolic-link targets are preserved without
    /// applying extraction policy. A late traversal or validation failure may
    /// leave partial output and poison this encoder.
    pub async fn add_directory<P: AsRef<Path>>(&mut self, source: P) -> Result<(), EncodeError> {
        self.ensure_active()?;
        let source = source.as_ref().to_path_buf();
        let initial_sequence = self.sequence;
        let result = self.write_directory(source).await;
        if result.is_err() && self.sequence != initial_sequence {
            self.poisoned = true;
        }
        result
    }

    async fn write_directory(&mut self, source: PathBuf) -> Result<(), EncodeError> {
        let mut traversal = DirectoryTraversal {
            entries: self.entries.clone(),
            buffer: Vec::new(),
        };
        let mut entries = stream_directory_entries(source)?;
        let result = self
            .write_directory_entries(&mut entries, &mut traversal)
            .await;
        let traversal_result = entries.finish().await;
        result?;
        traversal_result?;
        self.entries = traversal.entries;
        Ok(())
    }

    async fn write_directory_entries(
        &mut self,
        entries: &mut TraversalStream,
        traversal: &mut DirectoryTraversal,
    ) -> Result<(), EncodeError> {
        while let Some(entries) = entries.recv().await {
            for entry in entries {
                match entry.kind {
                    TraversalKind::Directory => {
                        reserve_entry(
                            &mut traversal.entries,
                            &entry.archive_path,
                            ArchivedEntry::Directory { explicit: true },
                        )?;
                        self.write_member(PaxMember {
                            path: entry.archive_path.as_str(),
                            kind: MemberKind::Directory,
                            size: 0,
                            link_path: None,
                            executable: false,
                        })
                        .await?;
                    }
                    TraversalKind::Regular => {
                        reserve_entry(
                            &mut traversal.entries,
                            &entry.archive_path,
                            ArchivedEntry::Regular,
                        )?;
                        self.write_source_file(&entry, &mut traversal.buffer)
                            .await?;
                    }
                    TraversalKind::SymbolicLink { target } => {
                        reserve_entry(
                            &mut traversal.entries,
                            &entry.archive_path,
                            ArchivedEntry::SymbolicLink,
                        )?;
                        self.write_member(PaxMember {
                            path: entry.archive_path.as_str(),
                            kind: MemberKind::SymbolicLink,
                            size: 0,
                            link_path: Some(&target),
                            executable: false,
                        })
                        .await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn write_source_file(
        &mut self,
        entry: &TraversalEntry,
        buffer: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        let reusable_buffer = mem::take(buffer);
        let (returned_buffer, result) = prepare_source_file(&entry.source, reusable_buffer).await;
        *buffer = returned_buffer;
        let file = result?;
        let (size, executable) = file.metadata();
        self.write_member(PaxMember {
            path: entry.archive_path.as_str(),
            kind: MemberKind::Regular,
            size,
            link_path: None,
            executable,
        })
        .await?;
        match file {
            PreparedSourceFile::Buffered { .. } => {
                self.write_bytes(buffer).await?;
                self.write_padding(size).await
            }
            PreparedSourceFile::Streaming { file, .. } => {
                let mut file = tokio::fs::File::from_std(file);
                self.write_file_payload(&mut file, &entry.source, size, buffer)
                    .await?;
                self.write_padding(size).await
            }
        }
    }

    /// Writes the required two-zero-block terminator and returns the writer.
    pub async fn finish(mut self) -> Result<W, EncodeError> {
        self.ensure_active()?;
        self.write_bytes(end_marker_bytes()).await?;
        Ok(self.writer)
    }

    async fn write_member(&mut self, member: PaxMember<'_>) -> Result<(), EncodeError> {
        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| arithmetic_overflow("pax member sequence"))?;
        frame_pax_member_into(self.sequence, member, &mut self.framing_buffer)?;
        if let Err(source) = self.writer.write_all(&self.framing_buffer).await {
            self.poisoned = true;
            return Err(EncodeError::Write { source });
        }
        self.sequence = next_sequence;
        Ok(())
    }

    async fn write_file_payload(
        &mut self,
        file: &mut tokio::fs::File,
        path: &Path,
        size: u64,
        buffer: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        let chunk_len = usize::try_from(size.min(SOURCE_FILE_CHUNK_BYTES as u64))
            .map_err(|_| arithmetic_overflow("source file read buffer size"))?;
        buffer.resize(chunk_len, 0);
        let mut remaining = size;
        while remaining != 0 {
            let read_len = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| arithmetic_overflow("source file read size"))?;
            let len = file.read(&mut buffer[..read_len]).await.map_err(|source| {
                EncodeError::Filesystem {
                    operation: "read source file",
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            if len == 0 {
                return Err(changed_source_file(path.to_path_buf()));
            }
            self.write_bytes(&buffer[..len]).await?;
            remaining -= len as u64;
        }
        let mut extra = [0];
        if file
            .read(&mut extra)
            .await
            .map_err(|source| EncodeError::Filesystem {
                operation: "read source file",
                path: path.to_path_buf(),
                source,
            })?
            != 0
        {
            return Err(changed_source_file(path.to_path_buf()));
        }
        Ok(())
    }

    async fn write_padding(&mut self, size: u64) -> Result<(), EncodeError> {
        let padding = payload_padding(size);
        if !padding.is_empty() {
            self.write_bytes(padding).await?;
        }
        Ok(())
    }

    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        if let Err(source) = self.writer.write_all(bytes).await {
            self.poisoned = true;
            return Err(EncodeError::Write { source });
        }
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), EncodeError> {
        if self.poisoned {
            return Err(EncodeError::Poisoned);
        }
        Ok(())
    }
}

async fn prepare_source_file(
    path: &Path,
    buffer: Vec<u8>,
) -> (Vec<u8>, Result<PreparedSourceFile, EncodeError>) {
    let path = path.to_path_buf();
    with_reusable_buffer(buffer, move |buffer| {
        let file = std::fs::File::open(&path)
            .map_err(|source| filesystem_error("open source file", &path, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| filesystem_error("inspect source file", &path, source))?;
        if !metadata.is_file() {
            return Err(changed_source_file(path));
        }
        let size = metadata.len();
        let executable = is_executable(&metadata);
        if size > SOURCE_FILE_CHUNK_BYTES as u64 {
            return Ok(PreparedSourceFile::Streaming {
                file,
                size,
                executable,
            });
        }
        let read_limit = size
            .checked_add(1)
            .ok_or_else(|| arithmetic_overflow("buffered source file read limit"))?;
        buffer.clear();
        file.take(read_limit)
            .read_to_end(buffer)
            .map_err(|source| filesystem_error("read source file", &path, source))?;
        let actual_size = u64::try_from(buffer.len())
            .map_err(|_| arithmetic_overflow("buffered source file payload size"))?;
        if actual_size != size {
            return Err(changed_source_file(path));
        }
        Ok(PreparedSourceFile::Buffered { size, executable })
    })
    .await
}

impl PreparedSourceFile {
    fn metadata(&self) -> (u64, bool) {
        match self {
            Self::Buffered { size, executable }
            | Self::Streaming {
                size, executable, ..
            } => (*size, *executable),
        }
    }
}

/// A failure while creating a pure-pax archive.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// A wire-format member could not be framed.
    #[error(transparent)]
    Framing(#[from] FramingWriteError),
    /// Traversing a recursive encoding source failed.
    #[error(transparent)]
    Traversal(#[from] TraversalError),
    /// A requested archive path is not safe and portable.
    #[error("invalid archive path {path:?}: {reason}")]
    InvalidArchivePath {
        /// The rejected archive path.
        path: PathBuf,
        /// The reason the path is not accepted.
        reason: &'static str,
    },
    /// An archive path collides with a previously reserved entry.
    #[error("archive entry collides with existing path {path}")]
    PathCollision {
        /// The conflicting normalized archive path.
        path: String,
    },
    /// A source file changed while it was being archived.
    #[error("source file changed while archiving: {path}")]
    ChangedSourceFile {
        /// The unstable source path.
        path: PathBuf,
    },
    /// A source filesystem operation failed.
    #[error("failed to {operation} {path}: {source}")]
    Filesystem {
        /// The operation that failed.
        operation: &'static str,
        /// The affected source filesystem path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// A blocking filesystem operation failed to complete.
    #[error("failed to complete blocking archive filesystem operation: {0}")]
    BlockingTask(#[from] tokio::task::JoinError),
    /// Writing the output archive failed.
    #[error("failed to write archive output")]
    Write {
        /// The underlying writer error.
        #[source]
        source: io::Error,
    },
    /// The encoder cannot continue because a prior failure may have written bytes.
    #[error("archive encoder is poisoned after a previous partial write")]
    Poisoned,
    /// A size or sequence computation exceeded this API's range.
    #[error("arithmetic overflow while computing {context}")]
    ArithmeticOverflow {
        /// The failed computation.
        context: &'static str,
    },
}

#[derive(Clone, Debug)]
enum ArchivedEntry {
    Directory { explicit: bool },
    Regular,
    SymbolicLink,
}

#[derive(Debug)]
struct DirectoryTraversal {
    entries: HashMap<NormalizedPath, ArchivedEntry>,
    buffer: Vec<u8>,
}

enum PreparedSourceFile {
    Buffered {
        size: u64,
        executable: bool,
    },
    Streaming {
        file: std::fs::File,
        size: u64,
        executable: bool,
    },
}

fn reserve_entry(
    entries: &mut HashMap<NormalizedPath, ArchivedEntry>,
    path: &NormalizedPath,
    entry: ArchivedEntry,
) -> Result<(), EncodeError> {
    for (separator, _) in path.as_str().match_indices('/') {
        let ancestor = &path.as_str()[..separator];
        match entries.get(ancestor) {
            Some(ArchivedEntry::Directory { .. }) => {}
            Some(_) => {
                return Err(path_collision(ancestor));
            }
            None => {
                entries.insert(
                    path.prefix(separator),
                    ArchivedEntry::Directory { explicit: false },
                );
            }
        }
    }
    match (entries.get_mut(path.as_str()), entry) {
        (Some(ArchivedEntry::Directory { explicit: false }), ArchivedEntry::Directory { .. }) => {
            entries.insert(path.clone(), ArchivedEntry::Directory { explicit: true });
        }
        (Some(_), _) => {
            return Err(path_collision(path.as_str()));
        }
        (None, entry) => {
            entries.insert(path.clone(), entry);
        }
    }
    Ok(())
}

fn preflight_regular_entry(
    entries: &HashMap<NormalizedPath, ArchivedEntry>,
    path: &NormalizedPath,
) -> Result<Vec<NormalizedPath>, EncodeError> {
    let mut implicit_ancestors = Vec::new();
    for (separator, _) in path.as_str().match_indices('/') {
        let ancestor = &path.as_str()[..separator];
        match entries.get(ancestor) {
            Some(ArchivedEntry::Directory { .. }) => {}
            Some(_) => {
                return Err(path_collision(ancestor));
            }
            None => implicit_ancestors.push(path.prefix(separator)),
        }
    }
    if entries.contains_key(path.as_str()) {
        return Err(path_collision(path.as_str()));
    }
    Ok(implicit_ancestors)
}

pub(crate) fn normalize_archive_path(path: &Path) -> Result<NormalizedPath, EncodeError> {
    let invalid = |reason| invalid_archive_path(path, reason);
    let legalized = LegalizedPath::from_path(path).map_err(|error| match error {
        PathError::InvalidUtf8 => invalid("path is not valid UTF-8"),
        PathError::Unsafe { reason, .. } => invalid(reason),
    })?;
    if legalized.as_str().is_empty() {
        return Err(invalid("path is empty"));
    }
    if legalized.as_str().ends_with('/') {
        return Err(invalid("path has a trailing separator"));
    }
    let normalized = legalized.normalize().map_err(|error| match error {
        PathError::InvalidUtf8 => invalid("path is not valid UTF-8"),
        PathError::Unsafe { reason, .. } => invalid(reason),
    })?;
    if normalized.is_empty() {
        return Err(invalid("path normalizes to empty"));
    }
    Ok(normalized)
}

fn invalid_archive_path(path: &Path, reason: &'static str) -> EncodeError {
    EncodeError::InvalidArchivePath {
        path: path.to_path_buf(),
        reason,
    }
}

fn filesystem_error(operation: &'static str, path: &Path, source: io::Error) -> EncodeError {
    EncodeError::Filesystem {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn arithmetic_overflow(context: &'static str) -> EncodeError {
    EncodeError::ArithmeticOverflow { context }
}

fn changed_source_file(path: PathBuf) -> EncodeError {
    EncodeError::ChangedSourceFile { path }
}

fn path_collision(path: &str) -> EncodeError {
    EncodeError::PathCollision {
        path: path.to_owned(),
    }
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use tar_framing::{
        PaxKind,
        logical::TarReader,
        stream::{Frame, TarStream},
    };
    use tempfile::tempdir;
    use tokio_stream::StreamExt;

    use super::{traversal::DIRECTORY_TRAVERSAL_BATCH_ENTRIES, *};
    use crate::{
        decode::{Archive, DecodeError, DecodePolicy},
        test_support::ChunkedReader,
    };

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

    async fn encode_source_directory(source: &Path) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.add_directory(source).await.unwrap();
        encoder.finish().await.unwrap()
    }

    async fn extract_archive(bytes: Vec<u8>, dest: &Path) -> Result<(), DecodeError> {
        Archive::new(ChunkedReader::new(bytes, 17))
            .extract(dest, DecodePolicy::default())
            .await
    }

    #[tokio::test]
    async fn adds_manual_files_as_local_pax_members_and_round_trips() {
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

        let frames = TarStream::new(ChunkedReader::new(bytes.clone(), 17))
            .collect::<Vec<_>>()
            .await;
        assert!(frames.iter().all(|frame| {
            matches!(
                frame,
                Ok(Frame::Pax(pax)) if pax.kind == PaxKind::Local
            ) || matches!(frame, Ok(Frame::Header(_) | Frame::Data(_)))
        }));

        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        extract_archive(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("bin/tool")).unwrap(), b"run");
        assert_eq!(std::fs::read(dest.join("README")).unwrap(), b"hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_ne!(
                std::fs::metadata(dest.join("bin/tool"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
            assert_eq!(
                std::fs::metadata(dest.join("README"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
    }

    #[tokio::test]
    async fn rejects_invalid_manual_paths_and_collisions_without_poisoning() {
        let mut encoder = Encoder::new(Vec::new());
        for path in [
            "",
            ".",
            "a/..",
            "../escape",
            "a/../../escape",
            "/absolute",
            "C:/ambiguous",
            "trailing/",
        ] {
            assert!(
                matches!(
                    encoder.add_entry(path, b"", EntryMetadata::default()).await,
                    Err(EncodeError::InvalidArchivePath { .. })
                ),
                "{path}"
            );
        }
        encoder
            .add_entry("dir/file", b"first", EntryMetadata::default())
            .await
            .unwrap();
        assert!(matches!(
            encoder.entries.get("dir"),
            Some(ArchivedEntry::Directory { explicit: false })
        ));
        for (path, data) in [
            ("dir/file", b"second".as_slice()),
            ("dir/file/child", b"".as_slice()),
        ] {
            assert!(
                matches!(
                    encoder
                        .add_entry(path, data, EntryMetadata::default())
                        .await,
                    Err(EncodeError::PathCollision { .. })
                ),
                "{path}"
            );
        }
        encoder
            .add_entry("dir/other", b"ok", EntryMetadata::default())
            .await
            .unwrap();
        assert!(matches!(
            encoder.entries.get("dir/other"),
            Some(ArchivedEntry::Regular)
        ));
        encoder.finish().await.unwrap();
    }

    #[tokio::test]
    async fn canonicalizes_manual_paths_before_framing_and_collision_checks() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .add_entry(
                "dir/./nested/../file",
                b"contents",
                EntryMetadata::default(),
            )
            .await
            .unwrap();
        assert!(matches!(
            encoder.entries.get("dir/file"),
            Some(ArchivedEntry::Regular)
        ));
        assert!(matches!(
            encoder
                .add_entry("dir//file", b"duplicate", EntryMetadata::default())
                .await,
            Err(EncodeError::PathCollision { path }) if path == "dir/file"
        ));

        let bytes = encoder.finish().await.unwrap();
        extract_archive(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("dir/file")).unwrap(), b"contents");
    }

    #[tokio::test]
    async fn write_failures_poison_the_encoder() {
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
    }

    #[tokio::test]
    async fn recursively_adds_sorted_directory_members() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("tree");
        std::fs::create_dir_all(source.join("sub")).unwrap();
        std::fs::write(source.join("z"), "last").unwrap();
        std::fs::write(source.join("a"), "first").unwrap();
        std::fs::write(source.join("sub/file"), "nested").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(source.join("a"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }

        let bytes = encode_source_directory(&source).await;
        let mut reader = TarReader::new(ChunkedReader::new(bytes.clone(), 17));
        let mut paths = Vec::new();
        while let Some(member) = reader.next_frame().await.unwrap() {
            paths.push(String::from_utf8(member.effective_path().unwrap().into_owned()).unwrap());
            member.payload.skip().await.unwrap();
        }
        assert_eq!(
            paths,
            ["tree", "tree/a", "tree/sub", "tree/sub/file", "tree/z"]
        );

        let dest = temp.path().join("out");
        extract_archive(bytes, &dest).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("tree/sub/file")).unwrap(),
            "nested"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_ne!(
                std::fs::metadata(dest.join("tree/a"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
    }

    #[tokio::test]
    async fn recursively_encodes_streamed_and_mixed_source_files() {
        for (case, files) in [
            (
                "streamed",
                vec![("large", vec![b'x'; SOURCE_FILE_CHUNK_BYTES + 17])],
            ),
            (
                "mixed",
                vec![
                    ("a-small", b"first".to_vec()),
                    ("m-large", vec![b'x'; SOURCE_FILE_CHUNK_BYTES + 17]),
                    ("z-small", b"last".to_vec()),
                ],
            ),
        ] {
            let temp = tempdir().unwrap();
            let source = temp.path().join("tree");
            std::fs::create_dir(&source).unwrap();
            for (name, contents) in &files {
                std::fs::write(source.join(name), contents).unwrap();
            }

            let bytes = encode_source_directory(&source).await;
            let dest = temp.path().join("out");
            extract_archive(bytes, &dest).await.unwrap();
            for (name, contents) in files {
                assert_eq!(
                    std::fs::read(dest.join("tree").join(name)).unwrap(),
                    contents,
                    "{case}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symbolic_link_roots_before_writing() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let source = temp.path().join("source");
        symlink(&target, &source).unwrap();

        let mut encoder = Encoder::new(Vec::new());
        assert!(matches!(
            encoder.add_directory(&source).await,
            Err(EncodeError::Traversal(
                TraversalError::SourceNotDirectory { .. }
            ))
        ));
        assert!(encoder.writer.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recursively_preserves_symlinks_for_extraction_policy_to_validate() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let source = temp.path().join("safe");
        std::fs::create_dir_all(source.join("sub")).unwrap();
        std::fs::write(source.join("sub/file"), "contents").unwrap();
        symlink("sub", source.join("directory")).unwrap();
        symlink("directory/file", source.join("file")).unwrap();

        let bytes = encode_source_directory(&source).await;
        let dest = temp.path().join("out");
        extract_archive(bytes, &dest).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("safe/file")).unwrap(),
            "contents"
        );

        let source = temp.path().join("escape");
        std::fs::create_dir(&source).unwrap();
        symlink("../../outside", source.join("link")).unwrap();
        let bytes = encode_source_directory(&source).await;
        assert!(matches!(
            extract_archive(bytes, &temp.path().join("escape-out")).await,
            Err(DecodeError::UnsafePath {
                context: "symbolic-link target",
                ..
            })
        ));

        let source = temp.path().join("dangling");
        std::fs::create_dir(&source).unwrap();
        symlink("missing", source.join("link")).unwrap();
        let bytes = encode_source_directory(&source).await;
        let dest = temp.path().join("dangling-out");
        extract_archive(bytes, &dest).await.unwrap();
        assert_eq!(
            std::fs::read_link(dest.join("dangling/link")).unwrap(),
            Path::new("missing")
        );

        let source = temp.path().join("cycle");
        std::fs::create_dir(&source).unwrap();
        symlink("link", source.join("link")).unwrap();
        let bytes = encode_source_directory(&source).await;
        assert!(matches!(
            extract_archive(bytes, &temp.path().join("cycle-out")).await,
            Err(DecodeError::InvalidLink { .. })
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn emits_repeated_inodes_as_independent_regular_files_and_rejects_sockets() {
        use std::os::unix::net::UnixListener;

        let temp = tempdir().unwrap();
        let source = temp.path().join("links");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("one"), "contents").unwrap();
        std::fs::hard_link(source.join("one"), source.join("two")).unwrap();

        let bytes = encode_source_directory(&source).await;
        let mut reader = TarReader::new(ChunkedReader::new(bytes, 17));
        let mut regular = 0;
        while let Some(member) = reader.next_frame().await.unwrap() {
            if member.header.kind == MemberKind::Regular {
                regular += 1;
            }
            member.payload.skip().await.unwrap();
        }
        assert_eq!(regular, 2);

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
        assert!(encoder.writer.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn late_recursive_errors_poison_partial_directory_output() {
        use std::os::unix::net::UnixListener;

        let temp = tempdir().unwrap();
        let source = temp.path().join("tree");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        for index in 0..DIRECTORY_TRAVERSAL_BATCH_ENTRIES {
            std::fs::write(source.join(format!("file-{index:03}")), "contents").unwrap();
        }
        let _listener = UnixListener::bind(source.join("nested/listener")).unwrap();

        let mut encoder = Encoder::new(Vec::new());
        assert!(matches!(
            encoder.add_directory(&source).await,
            Err(EncodeError::Traversal(
                TraversalError::UnsupportedFilesystemType { .. }
            ))
        ));
        assert!(!encoder.writer.is_empty());
        assert!(matches!(
            encoder
                .add_entry("other", b"", EntryMetadata::default())
                .await,
            Err(EncodeError::Poisoned)
        ));
    }

    #[tokio::test]
    async fn late_recursive_collisions_poison_partial_directory_output() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("tree");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file"), "new").unwrap();

        let mut encoder = Encoder::new(Vec::new());
        encoder
            .add_entry("tree/file", b"existing", EntryMetadata::default())
            .await
            .unwrap();
        let prior_len = encoder.writer.len();
        assert!(matches!(
            encoder.add_directory(&source).await,
            Err(EncodeError::PathCollision { .. })
        ));
        assert!(encoder.writer.len() > prior_len);
        assert!(matches!(
            encoder
                .add_entry("other", b"", EntryMetadata::default())
                .await,
            Err(EncodeError::Poisoned)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_non_utf8_source_names_before_writing() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let temp = tempdir().unwrap();
        let source = temp.path().join("tree");
        std::fs::create_dir(&source).unwrap();
        let invalid = OsString::from_vec(vec![0xff]);
        assert!(matches!(
            normalize_archive_path(Path::new(&invalid)),
            Err(EncodeError::InvalidArchivePath { .. })
        ));
        if std::fs::write(source.join(&invalid), "contents").is_err() {
            return;
        }

        let mut encoder = Encoder::new(Vec::new());
        assert!(matches!(
            encoder.add_directory(&source).await,
            Err(EncodeError::Traversal(
                TraversalError::NonUtf8SourcePath { .. }
            ))
        ));
        assert!(encoder.writer.is_empty());
    }
}
