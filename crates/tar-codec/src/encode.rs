//! Deterministic high-level encoding for pure pax tar archives.
//!
//! The encoder emits one local pax header before every member. Compression is
//! intentionally left to callers, which may wrap the underlying async writer.
//! [`EncodePolicy`] controls validation of member names and symbolic-link
//! targets without imposing extraction-specific path containment.

mod traversal;

pub use self::traversal::TraversalError;

use std::{
    collections::HashMap,
    io::{self, Read},
    mem,
    path::{Path, PathBuf},
};

use tar_framing::{
    UstarKind,
    write::{
        FramingWriteError, PaxMember, end_marker_bytes, frame_pax_member_into, payload_padding,
    },
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use self::traversal::{TraversalEntry, TraversalKind, TraversalStream, stream_directory_entries};
use crate::{NameValidator, blocking::with_reusable_buffer, name::NameValidation};

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

/// Controls which UTF-8 archive names the encoder accepts.
#[derive(Clone, Copy, Debug)]
pub struct EncodePolicy {
    name_validation: NameValidation,
}

impl Default for EncodePolicy {
    fn default() -> Self {
        Self {
            name_validation: NameValidation::Default,
        }
    }
}

impl EncodePolicy {
    /// Configures validation for member names and symbolic-link targets.
    ///
    /// Passing [`None`] disables configurable name validation. UTF-8 and
    /// wire-format requirements still apply.
    pub fn name_validator(mut self, validator: Option<NameValidator>) -> Self {
        self.name_validation = NameValidation::from_validator(validator);
        self
    }
}

/// A one-pass asynchronous encoder for deterministic pure-pax archives.
pub struct Encoder<W> {
    writer: W,
    policy: EncodePolicy,
    sequence: u64,
    entries: HashMap<String, ArchivedEntry>,
    framing_buffer: Vec<u8>,
    poisoned: bool,
}

impl<W> Encoder<W> {
    /// Creates an encoder writing an uncompressed pax archive into `writer`.
    pub fn new(writer: W) -> Self {
        Self::with_policy(writer, EncodePolicy::default())
    }

    /// Creates an encoder using `policy`.
    pub fn with_policy(writer: W, policy: EncodePolicy) -> Self {
        Self {
            writer,
            policy,
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
        let path = archive_name(path.as_ref(), self.policy.name_validation, "member path")?;
        let implicit_ancestors = preflight_regular_entry(&self.entries, &path)?;
        let data = data.as_ref();
        let size = u64::try_from(data.len())
            .map_err(|_| arithmetic_overflow("manual entry payload size"))?;
        self.write_member(PaxMember {
            path: &path,
            kind: UstarKind::Regular,
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
        let mut entries = stream_directory_entries(source, self.policy.name_validation)?;
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
                            path: &entry.archive_path,
                            kind: UstarKind::Directory,
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
                            path: &entry.archive_path,
                            kind: UstarKind::SymbolicLink,
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
            path: &entry.archive_path,
            kind: UstarKind::Regular,
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
    /// A requested archive path cannot be represented by the UTF-8 encoder.
    #[error("invalid archive path {path:?}: {reason}")]
    InvalidArchivePath {
        /// The rejected archive path.
        path: PathBuf,
        /// The reason the path cannot be represented.
        reason: &'static str,
    },
    /// An archive name was rejected by the configured [`EncodePolicy`].
    #[error("archive {context} rejected by encode policy: {value:?}")]
    NameRejected {
        /// The role of the rejected archive text.
        context: &'static str,
        /// The rejected UTF-8 value.
        value: String,
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
    entries: HashMap<String, ArchivedEntry>,
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
    entries: &mut HashMap<String, ArchivedEntry>,
    path: &str,
    entry: ArchivedEntry,
) -> Result<(), EncodeError> {
    for (separator, _) in path.match_indices('/') {
        let ancestor = &path[..separator];
        match entries.get(ancestor) {
            Some(ArchivedEntry::Directory { .. }) => {}
            Some(_) => {
                return Err(path_collision(ancestor));
            }
            None => {
                entries.insert(
                    ancestor.to_owned(),
                    ArchivedEntry::Directory { explicit: false },
                );
            }
        }
    }
    match (entries.get_mut(path), entry) {
        (Some(ArchivedEntry::Directory { explicit: false }), ArchivedEntry::Directory { .. }) => {
            entries.insert(path.to_owned(), ArchivedEntry::Directory { explicit: true });
        }
        (Some(_), _) => {
            return Err(path_collision(path));
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
                return Err(path_collision(ancestor));
            }
            None => implicit_ancestors.push(ancestor.to_owned()),
        }
    }
    if entries.contains_key(path) {
        return Err(path_collision(path));
    }
    Ok(implicit_ancestors)
}

fn archive_name(
    path: &Path,
    validation: NameValidation,
    context: &'static str,
) -> Result<String, EncodeError> {
    let Some(name) = path.to_str() else {
        return Err(EncodeError::InvalidArchivePath {
            path: path.to_path_buf(),
            reason: "path is not valid UTF-8",
        });
    };
    if !validation.accepts(name) {
        return Err(EncodeError::NameRejected {
            context,
            value: name.to_owned(),
        });
    }
    Ok(name.to_owned())
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
