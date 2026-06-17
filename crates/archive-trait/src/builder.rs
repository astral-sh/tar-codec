//! Format-neutral archive construction and recursive filesystem traversal.

mod traversal;

use std::{
    collections::HashMap,
    io::{self, Read},
    mem,
    path::{Path, PathBuf},
};

use thiserror::Error;
use tokio::io::AsyncReadExt;

pub use self::traversal::TraversalError;
use self::traversal::{TraversalEntry, TraversalKind, TraversalStream, stream_directory_entries};
use crate::{NameValidator, name::NameValidation};

const SOURCE_FILE_CHUNK_BYTES: usize = 1024 * 1024;

/// Minimal regular-file metadata accepted by [`ArchiveBuilder::add_entry`].
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

    /// Returns whether this entry carries executable intent.
    #[doc(hidden)]
    pub fn is_executable(self) -> bool {
        self.executable
    }
}

/// Controls format-neutral archive construction behavior.
#[derive(Clone, Copy, Debug, Default)]
pub struct BuilderPolicy {
    name_validation: NameValidation,
    symlink_policy: SymlinkPolicy,
}

/// Controls how source symbolic links are handled during recursive builds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SymlinkPolicy {
    /// Reject recursive sources containing symbolic links.
    #[default]
    Reject,
    /// Preserve symbolic links as link members in the resulting archive.
    Preserve,
    // TODO: Consider adding some kind of "Dereference" policy in the future,
    // where symlinks get followed and replaced with their normal file/directory
    // contents.
}

impl BuilderPolicy {
    /// Configures validation for member names and preserved symbolic-link targets.
    ///
    /// Passing [`None`] disables configurable name validation. UTF-8 and
    /// archive-format requirements still apply.
    pub fn name_validator(mut self, validator: Option<NameValidator>) -> Self {
        self.name_validation = NameValidation::from_validator(validator);
        self
    }

    /// Configures how recursive builds handle source symbolic links.
    ///
    /// Symbolic links are **rejected by default**. Use
    /// [`SymlinkPolicy::Preserve`] to write link members instead.
    pub fn symlink_policy(mut self, policy: SymlinkPolicy) -> Self {
        self.symlink_policy = policy;
        self
    }
}

/// Shared state used by format-specific [`ArchiveBuilder`] implementations.
///
/// This type is public only so external archive formats can implement the
/// format hooks. Its API is not intended for direct archive construction.
#[doc(hidden)]
pub struct BuilderState {
    policy: BuilderPolicy,
    entries: HashMap<String, ArchivedEntry>,
    source_buffer: Vec<u8>,
    poisoned: bool,
}

impl BuilderState {
    /// Creates shared builder state using `policy`.
    #[doc(hidden)]
    pub fn new(policy: BuilderPolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
            source_buffer: Vec::new(),
            poisoned: false,
        }
    }

    /// Returns an error when a previous partial write poisoned this builder.
    #[doc(hidden)]
    pub fn ensure_active<E>(&self) -> Result<(), BuildError<E>> {
        if self.poisoned {
            return Err(BuildError::Poisoned);
        }
        Ok(())
    }

    /// Marks this builder unusable after a potentially partial output write.
    #[doc(hidden)]
    pub fn poison(&mut self) {
        self.poisoned = true;
    }
}

/// A format-neutral payload supplied to an archive format implementation.
///
/// This type is public only for the doc-hidden [`ArchiveBuilder`] hooks.
#[doc(hidden)]
pub struct EntryPayload<'a> {
    size: u64,
    inner: EntryPayloadInner<'a>,
}

enum EntryPayloadInner<'a> {
    Borrowed {
        bytes: &'a [u8],
        yielded: bool,
    },
    Buffered {
        buffer: Vec<u8>,
        yielded: bool,
    },
    Streaming {
        file: tokio::fs::File,
        path: PathBuf,
        buffer: Vec<u8>,
        remaining: u64,
        validated_end: bool,
    },
}

impl EntryPayload<'_> {
    /// Returns the payload size declared before format framing begins.
    #[doc(hidden)]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the next payload chunk and validates source-file stability.
    #[doc(hidden)]
    pub async fn next_chunk<E>(&mut self) -> Result<Option<&[u8]>, BuildError<E>> {
        match &mut self.inner {
            EntryPayloadInner::Borrowed { bytes, yielded } => {
                if *yielded || bytes.is_empty() {
                    return Ok(None);
                }
                *yielded = true;
                Ok(Some(bytes))
            }
            EntryPayloadInner::Buffered { buffer, yielded } => {
                if *yielded || buffer.is_empty() {
                    return Ok(None);
                }
                *yielded = true;
                Ok(Some(buffer))
            }
            EntryPayloadInner::Streaming {
                file,
                path,
                buffer,
                remaining,
                validated_end,
            } => {
                if *remaining == 0 {
                    if *validated_end {
                        return Ok(None);
                    }
                    let mut extra = [0];
                    if file
                        .read(&mut extra)
                        .await
                        .map_err(|source| filesystem_error("read source file", path, source))?
                        != 0
                    {
                        return Err(changed_source_file(path.to_path_buf()));
                    }
                    *validated_end = true;
                    return Ok(None);
                }
                let chunk_len = usize::try_from((*remaining).min(SOURCE_FILE_CHUNK_BYTES as u64))
                    .map_err(|_| arithmetic_overflow("source file read buffer size"))?;
                buffer.resize(chunk_len, 0);
                let length = file
                    .read(buffer)
                    .await
                    .map_err(|source| filesystem_error("read source file", path, source))?;
                if length == 0 {
                    return Err(changed_source_file(path.to_path_buf()));
                }
                *remaining -= u64::try_from(length)
                    .map_err(|_| arithmetic_overflow("source file read size"))?;
                Ok(Some(&buffer[..length]))
            }
        }
    }

    fn borrowed<E>(bytes: &[u8]) -> Result<EntryPayload<'_>, BuildError<E>> {
        let size = u64::try_from(bytes.len())
            .map_err(|_| arithmetic_overflow("manual entry payload size"))?;
        Ok(EntryPayload {
            size,
            inner: EntryPayloadInner::Borrowed {
                bytes,
                yielded: false,
            },
        })
    }

    fn into_buffer(self) -> Vec<u8> {
        match self.inner {
            EntryPayloadInner::Borrowed { .. } => Vec::new(),
            EntryPayloadInner::Buffered { buffer, .. }
            | EntryPayloadInner::Streaming { buffer, .. } => buffer,
        }
    }
}

/// A format-specific archive writer with format-neutral construction APIs.
#[expect(
    async_fn_in_trait,
    reason = "archive writers may be !Send and run on a local executor"
)]
pub trait ArchiveBuilder: Sized {
    /// The archive-format error returned while encoding entries.
    type Error;

    /// Returns the shared state used by the default builder operations.
    #[doc(hidden)]
    fn builder_state(&mut self) -> &mut BuilderState;

    /// Writes one regular-file member and its complete payload.
    ///
    /// Implementations must call [`EntryPayload::next_chunk`] through
    /// completion. If an error occurs after any output may have been written,
    /// they must call [`BuilderState::poison`] before returning it.
    #[doc(hidden)]
    async fn write_file_member(
        &mut self,
        path: &str,
        payload: &mut EntryPayload<'_>,
        metadata: EntryMetadata,
    ) -> Result<(), BuildError<Self::Error>>;

    /// Writes one directory member.
    ///
    /// Implementations must poison their state before returning an error if
    /// any output may have been written.
    #[doc(hidden)]
    async fn write_directory_member(&mut self, path: &str) -> Result<(), BuildError<Self::Error>>;

    /// Writes one symbolic-link member.
    ///
    /// Implementations must poison their state before returning an error if
    /// any output may have been written.
    #[doc(hidden)]
    async fn write_symbolic_link_member(
        &mut self,
        path: &str,
        target: &str,
    ) -> Result<(), BuildError<Self::Error>>;

    /// Adds one regular file from an in-memory byte buffer.
    async fn add_entry<P, D>(
        &mut self,
        path: P,
        data: D,
        metadata: EntryMetadata,
    ) -> Result<(), BuildError<Self::Error>>
    where
        P: AsRef<Path>,
        D: AsRef<[u8]>,
    {
        self.builder_state().ensure_active()?;
        let path = archive_name(
            path.as_ref(),
            self.builder_state().policy.name_validation,
            "member path",
        )?;
        let implicit_ancestors = preflight_regular_entry(&self.builder_state().entries, &path)?;
        let mut payload = EntryPayload::borrowed(data.as_ref())?;
        self.write_file_member(&path, &mut payload, metadata)
            .await?;
        for ancestor in implicit_ancestors {
            self.builder_state()
                .entries
                .insert(ancestor, ArchivedEntry::Directory { explicit: false });
        }
        self.builder_state()
            .entries
            .insert(path, ArchivedEntry::Regular);
        Ok(())
    }

    /// Recursively adds a filesystem directory beneath its UTF-8 basename.
    ///
    /// Entries are visited in deterministic sorted order and files are streamed
    /// with bounded memory. Source symbolic links are rejected by default;
    /// [`BuilderPolicy::symlink_policy`] can instead preserve them. A late
    /// traversal or validation failure may leave partial output and poison
    /// this builder.
    async fn add_directory<P: AsRef<Path>>(
        &mut self,
        source: P,
    ) -> Result<(), BuildError<Self::Error>> {
        self.builder_state().ensure_active()?;
        let source = source.as_ref().to_path_buf();
        let (validation, symlink_policy, entries, source_buffer) = {
            let state = self.builder_state();
            (
                state.policy.name_validation,
                state.policy.symlink_policy,
                state.entries.clone(),
                mem::take(&mut state.source_buffer),
            )
        };
        let mut traversal = DirectoryBuild {
            entries,
            source_buffer,
            emitted: false,
        };
        let mut entries = match stream_directory_entries(source, validation, symlink_policy) {
            Ok(entries) => entries,
            Err(error) => {
                self.builder_state().source_buffer = traversal.source_buffer;
                return Err(BuildError::Traversal(error));
            }
        };
        let write_result = write_directory_entries(self, &mut entries, &mut traversal).await;
        let traversal_result = entries.finish().await.map_err(BuildError::Traversal);
        let result = write_result.and(traversal_result);
        let state = self.builder_state();
        state.source_buffer = traversal.source_buffer;
        if result.is_ok() {
            state.entries = traversal.entries;
        } else if traversal.emitted {
            state.poison();
        }
        result
    }
}

async fn write_directory_entries<B: ArchiveBuilder>(
    builder: &mut B,
    entries: &mut TraversalStream,
    traversal: &mut DirectoryBuild,
) -> Result<(), BuildError<B::Error>> {
    while let Some(entries) = entries.recv().await {
        for entry in entries {
            match entry.kind {
                TraversalKind::Directory => {
                    reserve_entry(
                        &mut traversal.entries,
                        &entry.archive_path,
                        ArchivedEntry::Directory { explicit: true },
                    )?;
                    builder.write_directory_member(&entry.archive_path).await?;
                }
                TraversalKind::Regular => {
                    reserve_entry(
                        &mut traversal.entries,
                        &entry.archive_path,
                        ArchivedEntry::Regular,
                    )?;
                    write_source_file(builder, &entry, traversal).await?;
                }
                TraversalKind::SymbolicLink { target } => {
                    reserve_entry(
                        &mut traversal.entries,
                        &entry.archive_path,
                        ArchivedEntry::SymbolicLink,
                    )?;
                    builder
                        .write_symbolic_link_member(&entry.archive_path, &target)
                        .await?;
                }
            }
            traversal.emitted = true;
        }
    }
    Ok(())
}

async fn write_source_file<B: ArchiveBuilder>(
    builder: &mut B,
    entry: &TraversalEntry,
    traversal: &mut DirectoryBuild,
) -> Result<(), BuildError<B::Error>> {
    let buffer = mem::take(&mut traversal.source_buffer);
    let (buffer, result) = prepare_source_file(&entry.source, buffer).await;
    let (mut payload, executable) = match result {
        Ok(prepared) => prepared.into_payload(buffer),
        Err(error) => {
            traversal.source_buffer = buffer;
            return Err(error.into_build_error());
        }
    };
    let metadata = EntryMetadata::default().executable(executable);
    let result = builder
        .write_file_member(&entry.archive_path, &mut payload, metadata)
        .await;
    traversal.source_buffer = payload.into_buffer();
    result
}

struct DirectoryBuild {
    entries: HashMap<String, ArchivedEntry>,
    source_buffer: Vec<u8>,
    emitted: bool,
}

enum PreparedSourceFile {
    Buffered {
        size: u64,
        executable: bool,
    },
    Streaming {
        file: std::fs::File,
        path: PathBuf,
        size: u64,
        executable: bool,
    },
}

impl PreparedSourceFile {
    fn into_payload(self, buffer: Vec<u8>) -> (EntryPayload<'static>, bool) {
        match self {
            Self::Buffered { size, executable } => (
                EntryPayload {
                    size,
                    inner: EntryPayloadInner::Buffered {
                        buffer,
                        yielded: false,
                    },
                },
                executable,
            ),
            Self::Streaming {
                file,
                path,
                size,
                executable,
            } => (
                EntryPayload {
                    size,
                    inner: EntryPayloadInner::Streaming {
                        file: tokio::fs::File::from_std(file),
                        path,
                        buffer,
                        remaining: size,
                        validated_end: false,
                    },
                },
                executable,
            ),
        }
    }
}

async fn prepare_source_file(
    path: &Path,
    buffer: Vec<u8>,
) -> (Vec<u8>, Result<PreparedSourceFile, SourceError>) {
    let path = path.to_path_buf();
    with_reusable_buffer(buffer, move |buffer| {
        let file = std::fs::File::open(&path)
            .map_err(|source| SourceError::filesystem("open source file", &path, source))?;
        let metadata = file
            .metadata()
            .map_err(|source| SourceError::filesystem("inspect source file", &path, source))?;
        if !metadata.is_file() {
            return Err(SourceError::ChangedSourceFile { path });
        }
        let size = metadata.len();
        let executable = is_executable(&metadata);
        if size > SOURCE_FILE_CHUNK_BYTES as u64 {
            return Ok(PreparedSourceFile::Streaming {
                file,
                path,
                size,
                executable,
            });
        }
        let read_limit = size.checked_add(1).ok_or(SourceError::ArithmeticOverflow {
            context: "buffered source file read limit",
        })?;
        buffer.clear();
        file.take(read_limit)
            .read_to_end(buffer)
            .map_err(|source| SourceError::filesystem("read source file", &path, source))?;
        let actual_size =
            u64::try_from(buffer.len()).map_err(|_| SourceError::ArithmeticOverflow {
                context: "buffered source file payload size",
            })?;
        if actual_size != size {
            return Err(SourceError::ChangedSourceFile { path });
        }
        Ok(PreparedSourceFile::Buffered { size, executable })
    })
    .await
}

async fn with_reusable_buffer<T, F>(
    mut buffer: Vec<u8>,
    operation: F,
) -> (Vec<u8>, Result<T, SourceError>)
where
    T: Send + 'static,
    F: FnOnce(&mut Vec<u8>) -> Result<T, SourceError> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || {
        let result = operation(&mut buffer);
        (buffer, result)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => (Vec::new(), Err(SourceError::BlockingTask(error))),
    }
}

enum SourceError {
    ChangedSourceFile {
        path: PathBuf,
    },
    Filesystem {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    BlockingTask(tokio::task::JoinError),
    ArithmeticOverflow {
        context: &'static str,
    },
}

impl SourceError {
    fn filesystem(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Filesystem {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }

    fn into_build_error<E>(self) -> BuildError<E> {
        match self {
            Self::ChangedSourceFile { path } => BuildError::ChangedSourceFile { path },
            Self::Filesystem {
                operation,
                path,
                source,
            } => BuildError::Filesystem {
                operation,
                path,
                source,
            },
            Self::BlockingTask(error) => BuildError::BlockingTask(error),
            Self::ArithmeticOverflow { context } => BuildError::ArithmeticOverflow { context },
        }
    }
}

/// A failure while constructing an archive.
#[derive(Debug, Error)]
pub enum BuildError<E> {
    /// The archive format encoder failed.
    #[error(transparent)]
    Encoder(E),
    /// Traversing a recursive source failed.
    #[error(transparent)]
    Traversal(#[from] TraversalError),
    /// A requested archive path cannot be represented by the UTF-8 builder.
    #[error("invalid archive path {path:?}: {reason}")]
    InvalidArchivePath {
        /// The rejected archive path.
        path: PathBuf,
        /// The reason the path cannot be represented.
        reason: &'static str,
    },
    /// An archive name was rejected by the configured [`BuilderPolicy`].
    #[error("archive {context} rejected by builder policy: {value:?}")]
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
    /// The builder cannot continue because a prior failure may have written bytes.
    #[error("archive builder is poisoned after a previous partial write")]
    Poisoned,
    /// A size computation exceeded this API's range.
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

fn reserve_entry<E>(
    entries: &mut HashMap<String, ArchivedEntry>,
    path: &str,
    entry: ArchivedEntry,
) -> Result<(), BuildError<E>> {
    for (separator, _) in path.match_indices('/') {
        let ancestor = &path[..separator];
        match entries.get(ancestor) {
            Some(ArchivedEntry::Directory { .. }) => {}
            Some(_) => return Err(path_collision(ancestor)),
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
        (Some(_), _) => return Err(path_collision(path)),
        (None, entry) => {
            entries.insert(path.to_owned(), entry);
        }
    }
    Ok(())
}

fn preflight_regular_entry<E>(
    entries: &HashMap<String, ArchivedEntry>,
    path: &str,
) -> Result<Vec<String>, BuildError<E>> {
    let mut implicit_ancestors = Vec::new();
    for (separator, _) in path.match_indices('/') {
        let ancestor = &path[..separator];
        match entries.get(ancestor) {
            Some(ArchivedEntry::Directory { .. }) => {}
            Some(_) => return Err(path_collision(ancestor)),
            None => implicit_ancestors.push(ancestor.to_owned()),
        }
    }
    if entries.contains_key(path) {
        return Err(path_collision(path));
    }
    Ok(implicit_ancestors)
}

fn archive_name<E>(
    path: &Path,
    validation: NameValidation,
    context: &'static str,
) -> Result<String, BuildError<E>> {
    let Some(name) = path.to_str() else {
        return Err(BuildError::InvalidArchivePath {
            path: path.to_path_buf(),
            reason: "path is not valid UTF-8",
        });
    };
    if !validation.accepts(name) {
        return Err(BuildError::NameRejected {
            context,
            value: name.to_owned(),
        });
    }
    Ok(name.to_owned())
}

fn filesystem_error<E>(operation: &'static str, path: &Path, source: io::Error) -> BuildError<E> {
    BuildError::Filesystem {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn arithmetic_overflow<E>(context: &'static str) -> BuildError<E> {
    BuildError::ArithmeticOverflow { context }
}

fn changed_source_file<E>(path: PathBuf) -> BuildError<E> {
    BuildError::ChangedSourceFile { path }
}

fn path_collision<E>(path: &str) -> BuildError<E> {
    BuildError::PathCollision {
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
