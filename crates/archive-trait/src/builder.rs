//! Format-neutral archive construction.
//!
//! Archive formats implement [`ArchiveBuilder`] and wrap the resulting writer
//! in a stateful [`Builder`] to use the format-neutral construction APIs.

mod traversal;

use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
    io::{self, Read},
    mem,
    ops::Range,
    path::{Path, PathBuf},
};

use thiserror::Error;
use tokio::io::AsyncReadExt;

pub use self::traversal::TraversalError;
use self::traversal::{TraversalEntry, TraversalKind, TraversalStream, stream_directory_entries};
use crate::{NameValidator, name::NameValidation};

const BUFFERED_SOURCE_FILE_BYTES: usize = 1024 * 1024;
const SOURCE_FILE_CHUNK_BYTES: usize = 2 * 1024 * 1024;
// A preparation batch may exceed this target by one buffered file, so its
// payload storage remains below twice this value.
const SOURCE_FILE_PREPARATION_BATCH_BYTES: usize = BUFFERED_SOURCE_FILE_BYTES;

/// Minimal regular-file metadata accepted by [`Builder::add_entry`].
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

struct BuilderState {
    policy: BuilderPolicy,
    entries: HashMap<String, ArchivedEntry>,
    source_buffer: Vec<u8>,
    poisoned: bool,
}

impl BuilderState {
    fn new(policy: BuilderPolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
            source_buffer: Vec::new(),
            poisoned: false,
        }
    }

    fn ensure_active<E>(&self) -> Result<(), BuildError<E>> {
        if self.poisoned {
            return Err(BuildError::Poisoned);
        }
        Ok(())
    }

    // A backend write is provisionally poisoning. Completion clears this flag
    // before the returned failure is classified; cancellation leaves it set.
    fn begin_write(&mut self) {
        self.poisoned = true;
    }

    fn complete_write(&mut self) {
        self.poisoned = false;
    }

    fn poison(&mut self) {
        self.poisoned = true;
    }
}

/// A format-neutral, uncompressed payload supplied to an [`ArchiveBuilder`]
/// implementation.
pub struct EntryPayload<'a> {
    size: u64,
    inner: EntryPayloadInner<'a>,
}

enum EntryPayloadInner<'a> {
    Buffered {
        data: Cow<'a, [u8]>,
        yielded: bool,
    },
    Streaming {
        file: tokio::fs::File,
        path: PathBuf,
        buffer: Vec<u8>,
        remaining: u64,
        filled: usize,
    },
}

impl EntryPayload<'_> {
    /// Returns the logical, uncompressed source size in bytes.
    ///
    /// This is the total number of bytes yielded by [`Self::next_chunk`], not
    /// necessarily the size ultimately stored by the archive format.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the next chunk of logical, uncompressed source bytes.
    pub async fn next_chunk<E>(&mut self) -> Result<Option<&[u8]>, BuildError<E>> {
        match &mut self.inner {
            EntryPayloadInner::Buffered { data, yielded } => {
                if *yielded || data.is_empty() {
                    return Ok(None);
                }
                *yielded = true;
                Ok(Some(&data[..]))
            }
            EntryPayloadInner::Streaming {
                file,
                path,
                buffer,
                remaining,
                filled,
            } => read_streaming_chunk(file, path, buffer, remaining, filled).await,
        }
    }

    fn borrowed<E>(bytes: &[u8]) -> Result<EntryPayload<'_>, BuildError<E>> {
        let size = u64::try_from(bytes.len())
            .map_err(|_| arithmetic_overflow("manual entry payload size"))?;
        Ok(EntryPayload {
            size,
            inner: EntryPayloadInner::Buffered {
                data: Cow::Borrowed(bytes),
                yielded: false,
            },
        })
    }
}

async fn read_streaming_chunk<'a, E>(
    file: &mut tokio::fs::File,
    path: &Path,
    buffer: &'a mut Vec<u8>,
    remaining: &mut u64,
    filled: &mut usize,
) -> Result<Option<&'a [u8]>, BuildError<E>> {
    if *remaining == 0 {
        return Ok(None);
    }

    let chunk_size = (*remaining).min(SOURCE_FILE_CHUNK_BYTES as u64);
    let chunk_len = usize::try_from(chunk_size)
        .map_err(|_| arithmetic_overflow("source file read buffer size"))?;
    buffer.resize(chunk_len, 0);
    // Progress lives in the payload rather than this future, so cancelling and
    // retrying `EntryPayload::next_chunk` cannot discard completed reads.
    while *filled < chunk_len {
        let read = file
            .read(&mut buffer[*filled..])
            .await
            .map_err(|source| filesystem_error("read source file", path, source))?;
        if read == 0 {
            return Err(filesystem_error(
                "read source file",
                path,
                io::Error::new(io::ErrorKind::UnexpectedEof, "source file was truncated"),
            ));
        }
        *filled += read;
    }
    *remaining -= chunk_size;
    *filled = 0;
    Ok(Some(buffer))
}

/// A failure returned by an [`ArchiveBuilder`] format hook.
///
/// This distinguishes errors known to precede output from errors that may have
/// left a partial member in the output archive.
#[derive(Debug)]
pub struct BuildFailure<E> {
    error: BuildError<E>,
    // TODO: Maybe make all failures poisoning?
    // I'm not sure we really need the distinction here.
    poisons_builder: bool,
}

impl<E> BuildFailure<E> {
    /// Reports a failure that occurred before the hook wrote any output.
    pub fn recoverable(error: BuildError<E>) -> Self {
        Self {
            error,
            poisons_builder: false,
        }
    }

    /// Reports a failure that may have left partial output.
    pub fn poisoned(error: BuildError<E>) -> Self {
        Self {
            error,
            poisons_builder: true,
        }
    }

    fn into_parts(self) -> (BuildError<E>, bool) {
        (self.error, self.poisons_builder)
    }
}

/// A format-specific archive writer that can create a stateful [`Builder`].
///
/// The asynchronous methods on this trait are implementation hooks for
/// [`Builder`]. Archive construction callers must not invoke them directly;
/// doing so bypasses builder policy, collision tracking, and cancellation
/// poisoning. Use [`Self::builder`] or [`Self::builder_with_policy`] and then
/// the [`Builder`] APIs instead.
///
/// Hook implementations must return [`BuildFailure::recoverable`] only when the
/// failed invocation wrote no output. Any failure after output may have begun
/// must use [`BuildFailure::poisoned`].
#[expect(
    async_fn_in_trait,
    reason = "archive writers may be !Send and run on a local executor"
)]
pub trait ArchiveBuilder: Sized {
    /// The archive-format error returned while encoding entries.
    type Error;

    /// Wraps this format writer in a builder using default policy.
    ///
    /// Implementors should not override this default implementation.
    fn builder(self) -> Builder<Self> {
        Builder {
            backend: self,
            state: BuilderState::new(BuilderPolicy::default()),
        }
    }

    /// Wraps this format writer in a builder using `policy`.
    ///
    /// Implementors should not override this default implementation.
    fn builder_with_policy(self, policy: BuilderPolicy) -> Builder<Self> {
        Builder {
            backend: self,
            state: BuilderState::new(policy),
        }
    }

    /// Writes any format-specific archive terminator or index.
    async fn finish_archive(&mut self) -> Result<(), BuildFailure<Self::Error>>;

    /// Writes one regular-file member and its complete payload.
    ///
    /// Implementations must call [`EntryPayload::next_chunk`] through
    /// completion and classify failures using [`BuildFailure`].
    async fn write_file_member(
        &mut self,
        path: &str,
        payload: &mut EntryPayload<'_>,
        metadata: EntryMetadata,
    ) -> Result<(), BuildFailure<Self::Error>>;

    /// Writes one directory member.
    async fn write_directory_member(&mut self, path: &str)
    -> Result<(), BuildFailure<Self::Error>>;

    /// Writes one symbolic-link member.
    async fn write_symbolic_link_member(
        &mut self,
        path: &str,
        target: &str,
    ) -> Result<(), BuildFailure<Self::Error>>;
}

/// A stateful format-neutral archive construction engine.
///
/// Create this wrapper with [`ArchiveBuilder::builder`] or
/// [`ArchiveBuilder::builder_with_policy`].
pub struct Builder<B> {
    backend: B,
    state: BuilderState,
}

impl<B: ArchiveBuilder> Builder<B> {
    /// Adds one regular file from an in-memory byte buffer.
    pub async fn add_entry<P, D>(
        &mut self,
        path: P,
        data: D,
        metadata: EntryMetadata,
    ) -> Result<(), BuildError<B::Error>>
    where
        P: AsRef<Path>,
        D: AsRef<[u8]>,
    {
        self.state.ensure_active()?;
        let archive_path = path.as_ref();
        let Some(path) = archive_path.to_str() else {
            return Err(BuildError::InvalidArchivePath {
                path: archive_path.to_path_buf(),
                reason: "path is not valid UTF-8",
            });
        };
        if !self.state.policy.name_validation.accepts(path) {
            return Err(BuildError::NameRejected {
                context: "member path",
                value: path.to_owned(),
            });
        }
        let path = path.to_owned();
        let implicit_ancestors = preflight_regular_entry(&self.state.entries, &path)?;
        let mut payload = EntryPayload::borrowed(data.as_ref())?;
        self.state.begin_write();
        let result = self
            .backend
            .write_file_member(&path, &mut payload, metadata)
            .await;
        self.state.complete_write();
        self.resolve_hook(result)?;
        for ancestor in implicit_ancestors {
            self.state
                .entries
                .insert(ancestor, ArchivedEntry::Directory { explicit: false });
        }
        self.state.entries.insert(path, ArchivedEntry::NonDirectory);
        Ok(())
    }

    /// Recursively adds a filesystem directory beneath its UTF-8 basename.
    ///
    /// Entries are visited in deterministic sorted order and files are streamed
    /// with bounded memory. Source symbolic links are rejected by default;
    /// [`BuilderPolicy::symlink_policy`] can instead preserve them. A late
    /// traversal or validation failure may leave partial output and poison
    /// this builder.
    pub async fn add_directory<P: AsRef<Path>>(
        &mut self,
        source: P,
    ) -> Result<(), BuildError<B::Error>> {
        self.state.ensure_active()?;
        let source = source.as_ref().to_path_buf();
        let mut entries = stream_directory_entries(
            source,
            self.state.policy.name_validation,
            self.state.policy.symlink_policy,
        )
        .map_err(BuildError::Traversal)?;
        let mut traversal = DirectoryBuild {
            entries: self.state.entries.clone(),
            source_buffer: mem::take(&mut self.state.source_buffer),
            emitted: false,
        };
        self.state.begin_write();
        let write_result =
            write_directory_entries(&mut self.backend, &mut entries, &mut traversal).await;
        let traversal_result = entries
            .finish()
            .await
            .map_err(BuildError::Traversal)
            .map_err(BuildFailure::recoverable);
        self.state.complete_write();
        let result = write_result.and(traversal_result);
        self.state.source_buffer = traversal.source_buffer;
        match result {
            Ok(()) => {
                self.state.entries = traversal.entries;
                Ok(())
            }
            Err(error) => {
                let (error, hook_poisoned) = error.into_parts();
                if traversal.emitted || hook_poisoned {
                    self.state.poison();
                }
                Err(error)
            }
        }
    }

    /// Finalizes and consumes this archive builder.
    ///
    /// Callers that need to retain access to an output sink should lend it to
    /// the format writer before wrapping it rather than transferring ownership.
    pub async fn finish(mut self) -> Result<(), BuildError<B::Error>> {
        self.state.ensure_active()?;
        let result = self.backend.finish_archive().await;
        self.resolve_hook(result)
    }

    fn resolve_hook<T>(
        &mut self,
        result: Result<T, BuildFailure<B::Error>>,
    ) -> Result<T, BuildError<B::Error>> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                let (error, poisons_builder) = error.into_parts();
                if poisons_builder {
                    self.state.poison();
                }
                Err(error)
            }
        }
    }
}

async fn write_directory_entries<B: ArchiveBuilder>(
    builder: &mut B,
    entries: &mut TraversalStream,
    traversal: &mut DirectoryBuild,
) -> Result<(), BuildFailure<B::Error>> {
    while let Some(entries) = entries.recv().await {
        let mut entries = VecDeque::from(entries);
        while !entries.is_empty() {
            let buffer = mem::take(&mut traversal.source_buffer);
            let (prepared, remaining) = prepare_directory_entries(entries, buffer)
                .await
                .map_err(SourceError::into_build_error)
                .map_err(BuildFailure::recoverable)?;
            entries = remaining;
            let PreparedDirectoryBatch {
                entries: prepared_entries,
                mut buffer,
            } = prepared;
            let result =
                write_prepared_directory_entries(builder, prepared_entries, &mut buffer, traversal)
                    .await;
            traversal.source_buffer = buffer;
            result?;
        }
    }
    Ok(())
}

async fn write_prepared_directory_entries<B: ArchiveBuilder>(
    builder: &mut B,
    entries: Vec<PreparedTraversalEntry>,
    buffer: &mut Vec<u8>,
    traversal: &mut DirectoryBuild,
) -> Result<(), BuildFailure<B::Error>> {
    for entry in entries {
        match entry.kind {
            PreparedTraversalKind::Directory => {
                reserve_entry(
                    &mut traversal.entries,
                    &entry.archive_path,
                    ArchivedEntry::Directory { explicit: true },
                )
                .map_err(BuildFailure::recoverable)?;
                builder.write_directory_member(&entry.archive_path).await?;
            }
            PreparedTraversalKind::BufferedFile {
                range,
                size,
                executable,
            } => {
                reserve_entry(
                    &mut traversal.entries,
                    &entry.archive_path,
                    ArchivedEntry::NonDirectory,
                )
                .map_err(BuildFailure::recoverable)?;
                let data = buffer.get(range).ok_or_else(|| {
                    BuildFailure::recoverable(arithmetic_overflow(
                        "prepared source file buffer range",
                    ))
                })?;
                let mut payload = EntryPayload {
                    size,
                    inner: EntryPayloadInner::Buffered {
                        data: Cow::Borrowed(data),
                        yielded: false,
                    },
                };
                builder
                    .write_file_member(
                        &entry.archive_path,
                        &mut payload,
                        EntryMetadata::default().executable(executable),
                    )
                    .await?;
            }
            PreparedTraversalKind::StreamingFile {
                file,
                path,
                size,
                executable,
            } => {
                reserve_entry(
                    &mut traversal.entries,
                    &entry.archive_path,
                    ArchivedEntry::NonDirectory,
                )
                .map_err(BuildFailure::recoverable)?;
                let mut file = tokio::fs::File::from_std(file);
                file.set_max_buf_size(SOURCE_FILE_CHUNK_BYTES);
                let mut payload = EntryPayload {
                    size,
                    inner: EntryPayloadInner::Streaming {
                        file,
                        path,
                        buffer: mem::take(buffer),
                        remaining: size,
                        filled: 0,
                    },
                };
                let result = builder
                    .write_file_member(
                        &entry.archive_path,
                        &mut payload,
                        EntryMetadata::default().executable(executable),
                    )
                    .await;
                *buffer = match payload.inner {
                    EntryPayloadInner::Buffered {
                        data: Cow::Owned(buffer),
                        ..
                    } => buffer,
                    EntryPayloadInner::Streaming { buffer, .. } => buffer,
                    EntryPayloadInner::Buffered {
                        data: Cow::Borrowed(_),
                        ..
                    } => Vec::new(),
                };
                result?;
            }
            PreparedTraversalKind::SymbolicLink { target } => {
                reserve_entry(
                    &mut traversal.entries,
                    &entry.archive_path,
                    ArchivedEntry::NonDirectory,
                )
                .map_err(BuildFailure::recoverable)?;
                builder
                    .write_symbolic_link_member(&entry.archive_path, &target)
                    .await?;
            }
        }
        traversal.emitted = true;
    }
    Ok(())
}

struct DirectoryBuild {
    entries: HashMap<String, ArchivedEntry>,
    source_buffer: Vec<u8>,
    emitted: bool,
}

struct PreparedDirectoryBatch {
    entries: Vec<PreparedTraversalEntry>,
    buffer: Vec<u8>,
}

struct PreparedTraversalEntry {
    archive_path: String,
    kind: PreparedTraversalKind,
}

enum PreparedTraversalKind {
    Directory,
    BufferedFile {
        range: Range<usize>,
        size: u64,
        executable: bool,
    },
    StreamingFile {
        file: std::fs::File,
        path: PathBuf,
        size: u64,
        executable: bool,
    },
    SymbolicLink {
        target: String,
    },
}

async fn prepare_directory_entries(
    mut entries: VecDeque<TraversalEntry>,
    mut buffer: Vec<u8>,
) -> Result<(PreparedDirectoryBatch, VecDeque<TraversalEntry>), SourceError> {
    tokio::task::spawn_blocking(move || {
        buffer.clear();
        let mut prepared = Vec::with_capacity(entries.len());
        while let Some(entry) = entries.pop_front() {
            let TraversalEntry {
                source,
                archive_path,
                kind,
            } = entry;
            let (kind, batch_complete) = match kind {
                TraversalKind::Directory => (PreparedTraversalKind::Directory, false),
                TraversalKind::Regular => prepare_regular_file(source, &mut buffer)?,
                TraversalKind::SymbolicLink { target } => {
                    (PreparedTraversalKind::SymbolicLink { target }, false)
                }
            };
            prepared.push(PreparedTraversalEntry { archive_path, kind });
            if batch_complete {
                break;
            }
        }
        Ok((
            PreparedDirectoryBatch {
                entries: prepared,
                buffer,
            },
            entries,
        ))
    })
    .await
    .map_err(SourceError::BlockingTask)?
}

fn prepare_regular_file(
    path: PathBuf,
    buffer: &mut Vec<u8>,
) -> Result<(PreparedTraversalKind, bool), SourceError> {
    let file = std::fs::File::open(&path)
        .map_err(|source| SourceError::filesystem("open source file", &path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| SourceError::filesystem("inspect source file", &path, source))?;
    if !metadata.is_file() {
        return Err(SourceError::filesystem(
            "inspect source file",
            &path,
            io::Error::other("source is not a regular file"),
        ));
    }
    let size = metadata.len();
    let executable = is_executable(&metadata);
    if size > BUFFERED_SOURCE_FILE_BYTES as u64 {
        return Ok((
            PreparedTraversalKind::StreamingFile {
                file,
                path,
                size,
                executable,
            },
            true,
        ));
    }
    let payload_size = usize::try_from(size).map_err(|_| SourceError::ArithmeticOverflow {
        context: "buffered source file size",
    })?;
    let start = buffer.len();
    let end = start
        .checked_add(payload_size)
        .ok_or(SourceError::ArithmeticOverflow {
            context: "buffered source batch size",
        })?;
    buffer.resize(end, 0);
    (&file)
        .read_exact(&mut buffer[start..end])
        .map_err(|source| SourceError::filesystem("read source file", &path, source))?;
    Ok((
        PreparedTraversalKind::BufferedFile {
            range: start..end,
            size,
            executable,
        },
        buffer.len() >= SOURCE_FILE_PREPARATION_BATCH_BYTES,
    ))
}

enum SourceError {
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
    NonDirectory,
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
