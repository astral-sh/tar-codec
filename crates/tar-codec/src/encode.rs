//! Deterministic high-level encoding for pure pax tar archives.
//!
//! The encoder emits one local pax header before every member. Compression is
//! intentionally left to callers, which may wrap the underlying async writer.

use std::{
    collections::{HashMap, HashSet},
    io::{self, Read},
    mem,
    path::{Path, PathBuf},
};

use tar_framing::{
    BLOCK_SIZE, MemberKind,
    write::{FramingWriteError, PaxMember, end_marker, frame_pax_member_into},
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    entries: HashMap<String, ArchivedEntry>,
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
        let size = u64::try_from(data.len()).map_err(|_| EncodeError::ArithmeticOverflow {
            context: "manual entry payload size",
        })?;
        self.write_member(PaxMember {
            path: &path,
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
    /// The complete tree is scanned and validated before any bytes belonging
    /// to this directory are written. Files are streamed with bounded memory.
    pub async fn add_directory<P: AsRef<Path>>(&mut self, source: P) -> Result<(), EncodeError> {
        self.ensure_active()?;
        let source = source.as_ref().to_path_buf();
        // TODO: Revisit streaming traversal instead of a full manifest preflight.
        // This would reduce many-small overhead, but permit partial output and
        // require incremental collision and symbolic-link graph validation.
        let manifest = tokio::task::spawn_blocking(move || scan_directory(&source)).await??;
        let entries = reserve_manifest(&self.entries, &manifest)?;
        self.write_manifest(&manifest).await?;
        self.entries = entries;
        Ok(())
    }

    async fn write_manifest(&mut self, manifest: &[ManifestEntry]) -> Result<(), EncodeError> {
        let mut buffer = Vec::new();
        for entry in manifest {
            if let Err(error) = self.write_manifest_entry(entry, &mut buffer).await {
                self.poisoned = true;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Writes the required two-zero-block terminator and returns the writer.
    pub async fn finish(mut self) -> Result<W, EncodeError> {
        self.ensure_active()?;
        for block in end_marker() {
            self.write_bytes(&block).await?;
        }
        Ok(self.writer)
    }

    async fn write_manifest_entry(
        &mut self,
        entry: &ManifestEntry,
        buffer: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        match &entry.kind {
            ManifestKind::Directory => {
                self.write_member(PaxMember {
                    path: &entry.archive_path,
                    kind: MemberKind::Directory,
                    size: 0,
                    link_path: None,
                    executable: false,
                })
                .await
            }
            ManifestKind::SymbolicLink { target } => {
                self.write_member(PaxMember {
                    path: &entry.archive_path,
                    kind: MemberKind::SymbolicLink,
                    size: 0,
                    link_path: Some(target),
                    executable: false,
                })
                .await
            }
            ManifestKind::Regular { size, executable } => {
                let mut file = if *size <= SOURCE_FILE_CHUNK_BYTES as u64 {
                    let reusable_buffer = mem::take(buffer);
                    let (returned_buffer, result) =
                        read_small_source_file(&entry.source, *size, reusable_buffer).await;
                    *buffer = returned_buffer;
                    result?;
                    None
                } else {
                    Some(open_source_file(&entry.source, *size).await?)
                };
                self.write_member(PaxMember {
                    path: &entry.archive_path,
                    kind: MemberKind::Regular,
                    size: *size,
                    link_path: None,
                    executable: *executable,
                })
                .await?;
                if let Some(file) = &mut file {
                    self.write_file_payload(file, &entry.source, *size, buffer)
                        .await?;
                } else {
                    self.write_bytes(buffer).await?;
                }
                self.write_padding(*size).await
            }
        }
    }

    async fn write_member(&mut self, member: PaxMember<'_>) -> Result<(), EncodeError> {
        let next_sequence =
            self.sequence
                .checked_add(1)
                .ok_or(EncodeError::ArithmeticOverflow {
                    context: "pax member sequence",
                })?;
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
        let chunk_len =
            usize::try_from(size.min(SOURCE_FILE_CHUNK_BYTES as u64)).map_err(|_| {
                EncodeError::ArithmeticOverflow {
                    context: "source file read buffer size",
                }
            })?;
        buffer.resize(chunk_len, 0);
        let mut remaining = size;
        while remaining != 0 {
            let read_len = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
                EncodeError::ArithmeticOverflow {
                    context: "source file read size",
                }
            })?;
            let len = file.read(&mut buffer[..read_len]).await.map_err(|source| {
                EncodeError::Filesystem {
                    operation: "read source file",
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            if len == 0 {
                return Err(EncodeError::ChangedSourceFile {
                    path: path.to_path_buf(),
                });
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
            return Err(EncodeError::ChangedSourceFile {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    async fn write_padding(&mut self, size: u64) -> Result<(), EncodeError> {
        let remainder = size % BLOCK_SIZE as u64;
        if remainder != 0 {
            let padding = [0; BLOCK_SIZE];
            let len = usize::try_from(BLOCK_SIZE as u64 - remainder).map_err(|_| {
                EncodeError::ArithmeticOverflow {
                    context: "payload padding size",
                }
            })?;
            self.write_bytes(&padding[..len]).await?;
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

async fn open_source_file(path: &Path, expected_size: u64) -> Result<tokio::fs::File, EncodeError> {
    let path = path.to_path_buf();
    let file = tokio::task::spawn_blocking(move || open_verified_source_file(&path, expected_size))
        .await??;
    Ok(tokio::fs::File::from_std(file))
}

async fn read_small_source_file(
    path: &Path,
    expected_size: u64,
    mut buffer: Vec<u8>,
) -> (Vec<u8>, Result<(), EncodeError>) {
    let path = path.to_path_buf();
    match tokio::task::spawn_blocking(move || {
        let result = (|| {
            let file = open_verified_source_file(&path, expected_size)?;
            let read_limit =
                expected_size
                    .checked_add(1)
                    .ok_or(EncodeError::ArithmeticOverflow {
                        context: "buffered source file read limit",
                    })?;
            buffer.clear();
            file.take(read_limit)
                .read_to_end(&mut buffer)
                .map_err(|source| filesystem_error("read source file", &path, source))?;
            let actual_size =
                u64::try_from(buffer.len()).map_err(|_| EncodeError::ArithmeticOverflow {
                    context: "buffered source file payload size",
                })?;
            if actual_size != expected_size {
                return Err(EncodeError::ChangedSourceFile { path });
            }
            Ok(())
        })();
        (buffer, result)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => (Vec::new(), Err(error.into())),
    }
}

fn open_verified_source_file(
    path: &Path,
    expected_size: u64,
) -> Result<std::fs::File, EncodeError> {
    let file = std::fs::File::open(path)
        .map_err(|source| filesystem_error("open source file", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| filesystem_error("inspect source file", path, source))?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err(EncodeError::ChangedSourceFile {
            path: path.to_path_buf(),
        });
    }
    Ok(file)
}

/// A failure while creating a pure-pax archive.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// A wire-format member could not be framed.
    #[error(transparent)]
    Framing(#[from] FramingWriteError),
    /// A requested archive path is not safe and portable.
    #[error("invalid archive path {path:?}: {reason}")]
    InvalidArchivePath {
        /// The rejected archive path.
        path: PathBuf,
        /// The reason the path is not accepted.
        reason: &'static str,
    },
    /// A source path component cannot be represented by this UTF-8-only encoder.
    #[error("source path is not valid UTF-8: {path}")]
    NonUtf8SourcePath {
        /// The affected source filesystem path.
        path: PathBuf,
    },
    /// A symbolic-link target cannot be represented by this UTF-8-only encoder.
    #[error("symbolic-link target is not valid UTF-8: {path}")]
    NonUtf8LinkTarget {
        /// The affected symbolic-link source path.
        path: PathBuf,
    },
    /// The recursive source root is not a directory.
    #[error("source root is not a directory: {path}")]
    SourceNotDirectory {
        /// The rejected source root.
        path: PathBuf,
    },
    /// A recursive source contains a filesystem node outside the supported subset.
    #[error("unsupported filesystem entry type: {path}")]
    UnsupportedFilesystemType {
        /// The rejected source filesystem path.
        path: PathBuf,
    },
    /// A symbolic-link target cannot be safely represented within the archive.
    #[error("unsafe symbolic link {path} -> {target:?}: {reason}")]
    UnsafeSymlink {
        /// The archive path of the rejected link.
        path: String,
        /// The source link target.
        target: String,
        /// The rejection reason.
        reason: &'static str,
    },
    /// An archive path collides with a previously reserved entry.
    #[error("archive entry collides with existing path {path}")]
    PathCollision {
        /// The conflicting normalized archive path.
        path: String,
    },
    /// A source file changed after recursive preflight.
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
    /// A blocking filesystem scan failed to complete.
    #[error("failed to complete blocking archive scan: {0}")]
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
    SymbolicLink { target: String },
}

#[derive(Debug)]
struct ManifestEntry {
    source: PathBuf,
    archive_path: String,
    kind: ManifestKind,
}

#[derive(Debug)]
enum ManifestKind {
    Directory,
    Regular { size: u64, executable: bool },
    SymbolicLink { target: String },
}

fn scan_directory(source: &Path) -> Result<Vec<ManifestEntry>, EncodeError> {
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| filesystem_error("inspect source directory", source, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(EncodeError::SourceNotDirectory {
            path: source.to_path_buf(),
        });
    }
    let Some(name) = source.file_name().and_then(|name| name.to_str()) else {
        return Err(EncodeError::NonUtf8SourcePath {
            path: source.to_path_buf(),
        });
    };
    let archive_path = normalize_archive_path(Path::new(name))?;
    let mut entries = Vec::new();
    scan_directory_at(source, &archive_path, &mut entries)?;
    Ok(entries)
}

fn scan_directory_at(
    source: &Path,
    archive_path: &str,
    entries: &mut Vec<ManifestEntry>,
) -> Result<(), EncodeError> {
    entries.push(ManifestEntry {
        source: source.to_path_buf(),
        archive_path: archive_path.to_owned(),
        kind: ManifestKind::Directory,
    });
    let children = std::fs::read_dir(source)
        .map_err(|error| filesystem_error("read source directory", source, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| filesystem_error("read source directory", source, error))?;
    let mut children = children
        .into_iter()
        .map(|child| {
            let path = child.path();
            let Some(name) = child.file_name().to_str().map(str::to_owned) else {
                return Err(EncodeError::NonUtf8SourcePath { path });
            };
            Ok((name, path))
        })
        .collect::<Result<Vec<_>, _>>()?;
    children.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (name, path) in children {
        let child_archive_path =
            normalize_archive_path(Path::new(&format!("{archive_path}/{name}")))?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| filesystem_error("inspect source entry", &path, error))?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            scan_directory_at(&path, &child_archive_path, entries)?;
        } else if file_type.is_file() {
            entries.push(ManifestEntry {
                source: path,
                archive_path: child_archive_path,
                kind: ManifestKind::Regular {
                    size: metadata.len(),
                    executable: is_executable(&metadata),
                },
            });
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&path)
                .map_err(|error| filesystem_error("read symbolic link", &path, error))?;
            let Some(target) = target.to_str().map(str::to_owned) else {
                return Err(EncodeError::NonUtf8LinkTarget { path });
            };
            entries.push(ManifestEntry {
                source: path,
                archive_path: child_archive_path,
                kind: ManifestKind::SymbolicLink { target },
            });
        } else {
            return Err(EncodeError::UnsupportedFilesystemType { path });
        }
    }
    Ok(())
}

fn reserve_manifest(
    existing: &HashMap<String, ArchivedEntry>,
    manifest: &[ManifestEntry],
) -> Result<HashMap<String, ArchivedEntry>, EncodeError> {
    let mut entries = existing.clone();
    for entry in manifest {
        let archived = match &entry.kind {
            ManifestKind::Directory => ArchivedEntry::Directory { explicit: true },
            ManifestKind::Regular { .. } => ArchivedEntry::Regular,
            ManifestKind::SymbolicLink { target } => ArchivedEntry::SymbolicLink {
                target: target.clone(),
            },
        };
        reserve_entry(&mut entries, &entry.archive_path, archived)?;
    }
    for entry in manifest {
        if let ManifestKind::SymbolicLink { target } = &entry.kind {
            validate_symlink(&entries, &entry.archive_path, target)?;
        }
    }
    Ok(entries)
}

fn reserve_entry(
    entries: &mut HashMap<String, ArchivedEntry>,
    path: &str,
    entry: ArchivedEntry,
) -> Result<(), EncodeError> {
    let components = path.split('/').collect::<Vec<_>>();
    for end in 1..components.len() {
        let ancestor = components[..end].join("/");
        match entries.get(&ancestor) {
            Some(ArchivedEntry::Directory { .. }) => {}
            Some(_) => return Err(EncodeError::PathCollision { path: ancestor }),
            None => {
                entries.insert(ancestor, ArchivedEntry::Directory { explicit: false });
            }
        }
    }
    match (entries.get_mut(path), entry) {
        (Some(ArchivedEntry::Directory { explicit: false }), ArchivedEntry::Directory { .. }) => {
            entries.insert(path.to_owned(), ArchivedEntry::Directory { explicit: true });
        }
        (Some(_), _) => {
            return Err(EncodeError::PathCollision {
                path: path.to_owned(),
            });
        }
        (None, entry) => {
            entries.insert(path.to_owned(), entry);
        }
    }
    Ok(())
}

fn preflight_regular_entry(
    entries: &HashMap<String, ArchivedEntry>,
    path: &str,
) -> Result<Vec<String>, EncodeError> {
    let mut implicit_ancestors = Vec::new();
    for (separator, _) in path.match_indices('/') {
        let ancestor = &path[..separator];
        match entries.get(ancestor) {
            Some(ArchivedEntry::Directory { .. }) => {}
            Some(_) => {
                return Err(EncodeError::PathCollision {
                    path: ancestor.to_owned(),
                });
            }
            None => implicit_ancestors.push(ancestor.to_owned()),
        }
    }
    if entries.contains_key(path) {
        return Err(EncodeError::PathCollision {
            path: path.to_owned(),
        });
    }
    Ok(implicit_ancestors)
}

fn validate_symlink(
    entries: &HashMap<String, ArchivedEntry>,
    path: &str,
    target: &str,
) -> Result<(), EncodeError> {
    let mut resolved = resolve_link_target(path, target, &[])?;
    let mut visited = HashSet::new();
    loop {
        let components = resolved.split('/').collect::<Vec<_>>();
        let mut followed = false;
        for end in 1..=components.len() {
            let prefix = components[..end].join("/");
            if let Some(ArchivedEntry::SymbolicLink { target: nested }) = entries.get(&prefix) {
                if !visited.insert(prefix.clone()) {
                    return Err(unsafe_symlink(path, target, "symbolic-link cycle"));
                }
                resolved = resolve_link_target(&prefix, nested, &components[end..])?;
                followed = true;
                break;
            }
        }
        if followed {
            continue;
        }
        return match entries.get(&resolved) {
            Some(ArchivedEntry::Regular | ArchivedEntry::Directory { .. }) => Ok(()),
            _ => Err(unsafe_symlink(
                path,
                target,
                "target does not resolve to an archived file or directory",
            )),
        };
    }
}

fn resolve_link_target(
    path: &str,
    target: &str,
    remainder: &[&str],
) -> Result<String, EncodeError> {
    if target.is_empty() || target.contains('\0') || target.contains('\\') {
        return Err(unsafe_symlink(
            path,
            target,
            "target is not a portable path",
        ));
    }
    if Path::new(target).is_absolute() || has_windows_prefix(target) {
        return Err(unsafe_symlink(path, target, "absolute target"));
    }
    let mut components = path.split('/').rev().skip(1).collect::<Vec<_>>();
    components.reverse();
    for component in target.split('/').chain(remainder.iter().copied()) {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(unsafe_symlink(path, target, "target escapes archive root"));
                }
            }
            _ => components.push(component),
        }
    }
    if components.is_empty() {
        return Err(unsafe_symlink(
            path,
            target,
            "target resolves to archive root",
        ));
    }
    Ok(components.join("/"))
}

fn unsafe_symlink(path: &str, target: &str, reason: &'static str) -> EncodeError {
    EncodeError::UnsafeSymlink {
        path: path.to_owned(),
        target: target.to_owned(),
        reason,
    }
}

fn normalize_archive_path(path: &Path) -> Result<String, EncodeError> {
    let invalid = |reason| EncodeError::InvalidArchivePath {
        path: path.to_path_buf(),
        reason,
    };
    let Some(path) = path.to_str() else {
        return Err(invalid("path is not valid UTF-8"));
    };
    if path.is_empty() {
        return Err(invalid("path is empty"));
    }
    if Path::new(path).is_absolute() || has_windows_prefix(path) {
        return Err(invalid("path is absolute"));
    }
    if path.contains('\0') || path.contains('\\') {
        return Err(invalid("path contains an ambiguous separator or NUL byte"));
    }
    if path
        .split('/')
        .any(|component| matches!(component, "" | "." | ".."))
    {
        return Err(invalid(
            "path contains an empty, current, or parent component",
        ));
    }
    Ok(path.to_owned())
}

fn has_windows_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn filesystem_error(operation: &'static str, path: &Path, source: io::Error) -> EncodeError {
    EncodeError::Filesystem {
        operation,
        path: path.to_path_buf(),
        source,
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
        ArchiveFormat, PaxKind,
        logical::{LogicalFrame, TarReader},
        stream::{Frame, TarStream},
    };
    use tempfile::tempdir;
    use tokio::io::{AsyncRead, ReadBuf};
    use tokio_stream::StreamExt;

    use super::*;
    use crate::decode::{Archive, ExtractPolicy};

    struct VecReader {
        bytes: Vec<u8>,
        position: usize,
    }

    impl VecReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, position: 0 }
        }
    }

    impl AsyncRead for VecReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.position == self.bytes.len() {
                return Poll::Ready(Ok(()));
            }
            let len = buffer
                .remaining()
                .min(17)
                .min(self.bytes.len() - self.position);
            let end = self.position + len;
            buffer.put_slice(&self.bytes[self.position..end]);
            self.position = end;
            Poll::Ready(Ok(()))
        }
    }

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

        let frames = TarStream::new(VecReader::new(bytes.clone()))
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
        Archive::new(VecReader::new(bytes))
            .extract(&dest, ExtractPolicy::default())
            .await
            .unwrap();
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
        assert!(matches!(
            encoder
                .add_entry("/absolute", b"", EntryMetadata::default())
                .await,
            Err(EncodeError::InvalidArchivePath { .. })
        ));
        assert!(matches!(
            encoder
                .add_entry("C:/ambiguous", b"", EntryMetadata::default())
                .await,
            Err(EncodeError::InvalidArchivePath { .. })
        ));
        encoder
            .add_entry("dir/file", b"first", EntryMetadata::default())
            .await
            .unwrap();
        assert!(matches!(
            encoder.entries.get("dir"),
            Some(ArchivedEntry::Directory { explicit: false })
        ));
        assert!(matches!(
            encoder
                .add_entry("dir/file", b"second", EntryMetadata::default())
                .await,
            Err(EncodeError::PathCollision { .. })
        ));
        assert!(matches!(
            encoder
                .add_entry("dir/file/child", b"", EntryMetadata::default())
                .await,
            Err(EncodeError::PathCollision { .. })
        ));
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

        let mut encoder = Encoder::new(Vec::new());
        encoder.add_directory(&source).await.unwrap();
        let bytes = encoder.finish().await.unwrap();
        let mut reader = TarReader::new(VecReader::new(bytes.clone()));
        let mut paths = Vec::new();
        while let Some(frame) = reader.next_frame().await.unwrap() {
            match frame {
                LogicalFrame::GlobalPax(_) => panic!("encoder never writes global pax headers"),
                LogicalFrame::Member(member) => {
                    paths.push(
                        String::from_utf8(member.effective_path().unwrap().into_owned()).unwrap(),
                    );
                    member.payload.skip().await.unwrap();
                }
            }
        }
        assert_eq!(
            paths,
            ["tree", "tree/a", "tree/sub", "tree/sub/file", "tree/z"]
        );
        assert_eq!(reader.format(), Some(ArchiveFormat::Pax));

        let dest = temp.path().join("out");
        Archive::new(VecReader::new(bytes))
            .extract(&dest, ExtractPolicy::default())
            .await
            .unwrap();
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
    async fn recursively_streams_files_larger_than_the_buffered_threshold() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("tree");
        std::fs::create_dir(&source).unwrap();
        let contents = vec![b'x'; SOURCE_FILE_CHUNK_BYTES + 17];
        std::fs::write(source.join("large"), &contents).unwrap();

        let mut encoder = Encoder::new(Vec::new());
        encoder.add_directory(&source).await.unwrap();
        let bytes = encoder.finish().await.unwrap();
        let dest = temp.path().join("out");
        Archive::new(VecReader::new(bytes))
            .extract(&dest, ExtractPolicy::default())
            .await
            .unwrap();
        assert_eq!(std::fs::read(dest.join("tree/large")).unwrap(), contents);
    }

    #[tokio::test]
    async fn recursively_combines_buffered_and_streamed_source_files() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("tree");
        std::fs::create_dir(&source).unwrap();
        let large = vec![b'x'; SOURCE_FILE_CHUNK_BYTES + 17];
        std::fs::write(source.join("a-small"), "first").unwrap();
        std::fs::write(source.join("m-large"), &large).unwrap();
        std::fs::write(source.join("z-small"), "last").unwrap();

        let mut encoder = Encoder::new(Vec::new());
        encoder.add_directory(&source).await.unwrap();
        let bytes = encoder.finish().await.unwrap();
        let dest = temp.path().join("out");
        Archive::new(VecReader::new(bytes))
            .extract(&dest, ExtractPolicy::default())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("tree/a-small")).unwrap(),
            "first"
        );
        assert_eq!(std::fs::read(dest.join("tree/m-large")).unwrap(), large);
        assert_eq!(
            std::fs::read_to_string(dest.join("tree/z-small")).unwrap(),
            "last"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recursively_preserves_safe_symlinks_and_rejects_unsafe_graphs_before_writing() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let source = temp.path().join("safe");
        std::fs::create_dir_all(source.join("sub")).unwrap();
        std::fs::write(source.join("sub/file"), "contents").unwrap();
        symlink("sub", source.join("directory")).unwrap();
        symlink("directory/file", source.join("file")).unwrap();

        let mut encoder = Encoder::new(Vec::new());
        encoder.add_directory(&source).await.unwrap();
        let bytes = encoder.finish().await.unwrap();
        let dest = temp.path().join("out");
        Archive::new(VecReader::new(bytes))
            .extract(&dest, ExtractPolicy::default())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("safe/file")).unwrap(),
            "contents"
        );

        for (name, target) in [
            ("escape", "../../outside"),
            ("dangling", "missing"),
            ("cycle", "cycle"),
        ] {
            let source = temp.path().join(name);
            std::fs::create_dir(&source).unwrap();
            symlink(target, source.join("link")).unwrap();
            let mut encoder = Encoder::new(Vec::new());
            assert!(matches!(
                encoder.add_directory(&source).await,
                Err(EncodeError::UnsafeSymlink { .. })
            ));
            assert!(encoder.writer.is_empty());
        }
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

        let mut encoder = Encoder::new(Vec::new());
        encoder.add_directory(&source).await.unwrap();
        let bytes = encoder.finish().await.unwrap();
        let mut reader = TarReader::new(VecReader::new(bytes));
        let mut regular = 0;
        while let Some(frame) = reader.next_frame().await.unwrap() {
            if let LogicalFrame::Member(member) = frame {
                if member.header.kind == MemberKind::Regular {
                    regular += 1;
                }
                member.payload.skip().await.unwrap();
            }
        }
        assert_eq!(regular, 2);

        let source = temp.path().join("socket");
        std::fs::create_dir(&source).unwrap();
        let _listener = UnixListener::bind(source.join("listener")).unwrap();
        let mut encoder = Encoder::new(Vec::new());
        assert!(matches!(
            encoder.add_directory(&source).await,
            Err(EncodeError::UnsupportedFilesystemType { .. })
        ));
        assert!(encoder.writer.is_empty());
    }

    #[tokio::test]
    async fn detects_changed_source_files_and_poisons_partial_directory_output() {
        for contents in [b"longer contents".as_slice(), b""] {
            let temp = tempdir().unwrap();
            let source = temp.path().join("tree");
            std::fs::create_dir(&source).unwrap();
            std::fs::write(source.join("file"), "initial").unwrap();
            let manifest = scan_directory(&source).unwrap();
            std::fs::write(source.join("file"), contents).unwrap();

            let mut encoder = Encoder::new(Vec::new());
            assert!(matches!(
                encoder.write_manifest(&manifest).await,
                Err(EncodeError::ChangedSourceFile { .. })
            ));
            assert!(matches!(
                encoder
                    .add_entry("other", b"", EntryMetadata::default())
                    .await,
                Err(EncodeError::Poisoned)
            ));
        }

        let temp = tempdir().unwrap();
        let source = temp.path().join("tree");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("file"), "initial").unwrap();
        let manifest = scan_directory(&source).unwrap();
        std::fs::remove_file(source.join("file")).unwrap();
        std::fs::create_dir(source.join("file")).unwrap();

        let mut encoder = Encoder::new(Vec::new());
        assert!(matches!(
            encoder.write_manifest(&manifest).await,
            Err(EncodeError::ChangedSourceFile { .. })
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
            Err(EncodeError::NonUtf8SourcePath { .. })
        ));
        assert!(encoder.writer.is_empty());
    }
}
