//! Destination state and capability-relative filesystem operations.
//!
//! [`ExtractionRoot`] records archive-owned paths and anchors mutations beneath
//! one verified directory capability.

mod buffered;

use std::{
    borrow::Cow,
    collections::HashSet,
    fs as std_fs, io,
    marker::PhantomData,
    mem,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(unix)]
use cap_std::fs::OpenOptionsExt as _;
use cap_std::{
    ambient_authority,
    fs::{Dir, Metadata, OpenOptions},
};
use tokio::{fs::File, io::AsyncWriteExt};
#[cfg(windows)]
use {
    cap_std::fs::MetadataExt as _, std::os::windows::fs::MetadataExt as _,
    windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT,
};

use self::buffered::{BufferedFile, BufferedFileReplacement, write_buffered_files};
use super::{
    LinkPolicy,
    path::{ExtractMember, NormalizedPath, resolve_link_target, validate_symlink_target},
};
use crate::{
    ExtractError, MemberPayload,
    component_tree::{ComponentTree, NodeId, ROOT_NODE},
};

/// A symbolic link reserved until the completed archive graph can be validated.
#[derive(Debug)]
struct PendingSymlink {
    entry: EntryId,
    parent: EntryId,
    path: NormalizedPath,
    position: u64,
    target: String,
    resolved_target: NormalizedPath,
    requires_directory: bool,
}

impl PendingSymlink {
    fn error<E>(&self, reason: &'static str) -> ExtractError<E> {
        ExtractError::invalid_link(
            self.position,
            self.path.to_path_buf(),
            self.target.clone(),
            reason,
        )
    }
}

// Bound substitutions and cumulative path work while validating the archive graph.
const MAX_SYMLINK_EXPANSIONS: usize = 256;
const MAX_SYMLINK_RESOLUTION_WORK_BYTES: usize = 8 * 1024 * 1024;
const SYMLINK_RESOLUTION_LIMIT_EXCEEDED: &str =
    "symbolic-link target resolution work limit exceeded";

// Small files are validated in memory and written in one blocking task.
const BUFFERED_PAYLOAD_MAX_BYTES: usize = 1024 * 1024;

// Bound read-ahead while amortizing blocking-pool handoffs across small files.
const BUFFERED_FILE_BATCH_MAX_ENTRIES: usize = 64;
const BUFFERED_FILE_BATCH_MAX_BYTES: usize = 4 * 1024 * 1024;

// Balance reusable-buffer initialization against blocking write cadence.
const STREAMING_PAYLOAD_CHUNK_BYTES: usize = 2 * 1024 * 1024;

/// The latest archive-visible state and provenance of an extracted path.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ExtractedEntry {
    File,
    CreatedDirectory,
    AmbientDirectory,
    Symlink { index: usize },
}

impl ExtractedEntry {
    fn is_directory(self) -> bool {
        matches!(self, Self::CreatedDirectory | Self::AmbientDirectory)
    }
}

type EntryId = NodeId;

const ROOT_ENTRY: EntryId = ROOT_NODE;

/// Archive-owned path state stored as a component tree.
struct EntryTree(ComponentTree<Box<str>, ExtractedEntry>);

impl EntryTree {
    fn new() -> Self {
        Self(ComponentTree::new(Some(ExtractedEntry::AmbientDirectory)))
    }

    fn child(&self, parent: EntryId, component: &str) -> Option<EntryId> {
        self.0.child(parent, component)
    }

    fn ensure_child(&mut self, parent: EntryId, component: &str) -> EntryId {
        self.0
            .ensure_child_with(parent, component, || component.into())
    }

    fn find(&self, path: &NormalizedPath) -> Option<EntryId> {
        let mut entry = ROOT_ENTRY;
        for component in path.components() {
            entry = self.child(entry, component)?;
        }
        Some(entry)
    }

    fn find_parent_directory(&self, path: &NormalizedPath) -> Option<EntryId> {
        let mut entry = ROOT_ENTRY;
        for component in path.parent_components() {
            entry = self.child(entry, component)?;
            if !self.state(entry).is_some_and(ExtractedEntry::is_directory) {
                return None;
            }
        }
        Some(entry)
    }

    fn state(&self, entry: EntryId) -> Option<ExtractedEntry> {
        self.0.state(entry).copied()
    }

    fn state_for_path(&self, path: &NormalizedPath) -> Option<ExtractedEntry> {
        self.find(path).and_then(|entry| self.state(entry))
    }

    fn set_state(&mut self, entry: EntryId, state: ExtractedEntry) {
        self.0.set_state(entry, state);
    }

    fn clear_state(&mut self, entry: EntryId) {
        self.0.clear_state(entry);
    }

    fn has_active_children(&self, entry: EntryId) -> bool {
        self.0.has_active_children(entry)
    }
}

/// Why extraction requires a directory at a particular path.
///
/// Explicit directory members participate in normal exact-path overwrite
/// handling. Implicit parents may create or reuse directories, but must never
/// replace a non-directory entry.
#[derive(Clone, Copy, Eq, PartialEq)]
enum DirectoryPurpose {
    /// The archive contains a directory member at this exact path.
    ExplicitMember,
    /// A descendant member requires this path to be a directory.
    ImplicitParent,
}

/// How an extracted file should be opened.
#[derive(Clone, Copy)]
enum FileOpenMode {
    /// Create a new file with the archived executable intent.
    CreateNew { executable: bool },
    /// Truncate a file that was just created as a hard link.
    Truncate,
}

impl FileOpenMode {
    fn options(self) -> OpenOptions {
        let mut options = OpenOptions::new();
        options.write(true);
        match self {
            Self::CreateNew { executable } => {
                options.create_new(true);
                #[cfg(unix)]
                options.mode(if executable { 0o777 } else { 0o666 });
                #[cfg(not(unix))]
                let _ = executable;
            }
            Self::Truncate => {
                options.truncate(true);
            }
        }
        options
    }
}

/// Tracks destination capabilities and archive-owned state for one extraction.
pub(super) struct ExtractionRoot<E> {
    /// The capability anchoring all extraction filesystem operations.
    directory: Arc<Dir>,
    /// The most recently opened directory capability, used to keep nearby leaf
    /// operations cheap without retaining one descriptor per directory.
    directory_handle: Option<(EntryId, Arc<Dir>)>,
    /// Whether overwrites are allowed during extraction.
    allow_overwrites: bool,
    /// The latest state recorded for every path encountered by the extraction.
    entries: EntryTree,
    /// Append-only storage; duplicate paths invalidate earlier indices.
    symlinks: Vec<PendingSymlink>,
    /// Fully validated files awaiting ordered creation in one blocking task.
    buffered_files: Vec<BufferedFile>,
    /// Total payload size retained by [`Self::buffered_files`].
    buffered_file_bytes: usize,
    /// Initialized payload allocations recycled after each completed batch.
    buffered_file_buffers: Vec<Vec<u8>>,
    /// Signals an in-flight blocking batch when the extraction future is dropped.
    buffered_file_cancellation: Arc<AtomicBool>,
    /// Associates filesystem failures with the archive error type without owning it.
    error: PhantomData<fn() -> E>,
}

impl<E> Drop for ExtractionRoot<E> {
    fn drop(&mut self) {
        self.buffered_file_cancellation
            .store(true, Ordering::Release);
    }
}

/// The filesystem shape of a fully resolved symbolic-link target, used to
/// enforce directory-required path suffixes.
#[derive(Clone, Copy, Eq, PartialEq)]
enum TerminalKind {
    /// The target exists and is a directory.
    Directory,
    /// The target exists and is not a directory.
    NonDirectory,
    /// The target does not yet exist.
    Dangling,
}

/// The result of resolving a target through the archive's symbolic-link graph.
///
/// Resolution stops when it reaches either an entry whose provenance and kind
/// are known from this extraction, or a path whose terminal entry is not owned
/// by the extraction and therefore requires policy-dependent handling.
enum ResolvedTarget {
    /// The extraction root or an archive-created entry of the given kind.
    Known(TerminalKind),
    /// A normalized root-relative path not created by this extraction.
    Unowned(NormalizedPath),
}

/// Streams a large payload into an already-created file.
async fn write_payload<P: MemberPayload>(
    mut payload: P,
    chunk_buffer: &mut Vec<u8>,
    path: &NormalizedPath,
    mut file: File,
) -> Result<(), ExtractError<P::Error>> {
    loop {
        if !payload
            .next_chunk(chunk_buffer, STREAMING_PAYLOAD_CHUNK_BYTES)
            .await
            .map_err(ExtractError::Archive)?
        {
            break;
        }
        file.write_all(chunk_buffer)
            .await
            .map_err(|source| ExtractError::filesystem("write file", path.to_path_buf(), source))?;
    }
    file.flush()
        .await
        .map_err(|source| ExtractError::filesystem("flush file", path.to_path_buf(), source))?;
    Ok(())
}

// Member operations invoked by the extraction loop.
impl<E> ExtractionRoot<E> {
    /// Opens or creates a real directory and anchors extraction to its capability.
    pub(super) async fn open(
        destination: &Path,
        allow_overwrites: bool,
    ) -> Result<Self, ExtractError<E>> {
        let destination = destination.to_owned();
        let error_path = destination.clone();
        let directory = tokio::task::spawn_blocking(move || {
            match std_fs::symlink_metadata(&destination) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std_fs::create_dir_all(&destination)?;
                }
                Err(error) => return Err(error),
            }
            let metadata = std_fs::symlink_metadata(&destination)?;
            if ambient_metadata_is_link(&metadata) || !metadata.is_dir() {
                return Err(io::Error::other("destination is not a real directory"));
            }
            let path = std_fs::canonicalize(destination)?;
            let directory = Dir::open_ambient_dir(path, ambient_authority())?;
            let metadata = directory.dir_metadata()?;
            if metadata_is_link(&metadata) || !metadata.is_dir() {
                return Err(io::Error::other("destination is not a real directory"));
            }
            Ok(Arc::new(directory))
        })
        .await
        .map_err(ExtractError::<E>::BlockingTask)?
        .map_err(|source| {
            ExtractError::<E>::filesystem("open destination directory", error_path, source)
        })?;

        Ok(Self {
            directory,
            directory_handle: None,
            allow_overwrites,
            entries: EntryTree::new(),
            symlinks: Vec::new(),
            buffered_files: Vec::new(),
            buffered_file_bytes: 0,
            buffered_file_buffers: Vec::new(),
            buffered_file_cancellation: Arc::new(AtomicBool::new(false)),
            error: PhantomData,
        })
    }

    /// Extracts a regular file, validating small payloads before creating it.
    pub(super) async fn extract_file<P: MemberPayload<Error = E>>(
        &mut self,
        path: &NormalizedPath,
        size: u64,
        executable: bool,
        mut payload: P,
        chunk_buffer: &mut Vec<u8>,
        buffered_payload: &mut Vec<u8>,
    ) -> Result<(), ExtractError<E>> {
        if size <= BUFFERED_PAYLOAD_MAX_BYTES as u64 {
            if let Ok(payload_size) = usize::try_from(size) {
                buffered_payload.reserve(payload_size.saturating_sub(buffered_payload.len()));
            }
            // Collect the common single-chunk case directly into the final
            // validated buffer; only fragmented payloads need an extra copy.
            let first_chunk = match payload
                .next_chunk(buffered_payload, BUFFERED_PAYLOAD_MAX_BYTES)
                .await
            {
                Ok(first_chunk) => first_chunk,
                Err(error) => {
                    self.flush_buffered_files().await?;
                    return Err(ExtractError::Archive(error));
                }
            };
            if first_chunk {
                loop {
                    let next_chunk = match payload
                        .next_chunk(chunk_buffer, BUFFERED_PAYLOAD_MAX_BYTES)
                        .await
                    {
                        Ok(next_chunk) => next_chunk,
                        Err(error) => {
                            self.flush_buffered_files().await?;
                            return Err(ExtractError::Archive(error));
                        }
                    };
                    if !next_chunk {
                        break;
                    }
                    buffered_payload.extend_from_slice(chunk_buffer);
                }
            } else {
                // `next_chunk` preserves initialized storage at EOF, but this
                // member's validated contents are empty.
                buffered_payload.clear();
            }
            *buffered_payload = self
                .queue_buffered_file(path, executable, mem::take(buffered_payload))
                .await?;
            return Ok(());
        }
        self.flush_buffered_files().await?;
        let file = self.create_file(path, executable).await?;
        write_payload(payload, chunk_buffer, path, file).await
    }

    /// Creates or reuses the real directory at `path`.
    pub(super) async fn extract_directory(
        &mut self,
        path: &NormalizedPath,
    ) -> Result<(), ExtractError<E>> {
        self.flush_buffered_files().await?;
        if !path.is_empty() {
            let parent = self.ensure_parents(path).await?;
            let entry = self.entries.ensure_child(parent, leaf_name(path));
            self.ensure_directory(path, entry, parent, DirectoryPurpose::ExplicitMember)
                .await?;
        }
        Ok(())
    }

    /// Reserves a symbolic link for validation after all members are read.
    pub(super) async fn reserve_symlink(
        &mut self,
        member: &ExtractMember,
    ) -> Result<(), ExtractError<E>> {
        self.flush_buffered_files().await?;
        let target = validate_symlink_target(member.position, &member.path, &member.link_target)?;
        let parent = self.ensure_parents(&member.path).await?;
        let entry = self.entries.ensure_child(parent, leaf_name(&member.path));
        self.replace_leaf(&member.path, entry, parent).await?;
        let index = self.symlinks.len();
        let path = member.path.clone();
        self.entries
            .set_state(entry, ExtractedEntry::Symlink { index });
        self.symlinks.push(PendingSymlink {
            entry,
            parent,
            path,
            position: member.position,
            target: member.link_target.clone(),
            resolved_target: target.resolved_target,
            requires_directory: target.requires_directory,
        });
        Ok(())
    }

    /// Creates a hard link to a previously extracted file.
    ///
    /// A zero-sized member only adds another name for the target's inode. A
    /// nonzero payload replaces that shared inode's contents, so the target and
    /// all of its hard links observe the replacement.
    pub(super) async fn extract_hard_link<P: MemberPayload<Error = E>>(
        &mut self,
        member: &ExtractMember,
        size: u64,
        payload: P,
        chunk_buffer: &mut Vec<u8>,
    ) -> Result<(), ExtractError<E>> {
        self.flush_buffered_files().await?;
        let target_text = member.link_target.clone();
        let target = resolve_link_target(
            member.position,
            "hard-link target",
            &target_text,
            &NormalizedPath::default(),
        )?;
        let reason = if !matches!(
            self.entries.state_for_path(&target),
            Some(ExtractedEntry::File)
        ) {
            Some("hard-link target is not a previously extracted file")
        } else if target == member.path {
            Some("hard-link target is the member path")
        } else if member.path.starts_with(&target) {
            Some("hard-link target is an ancestor of the member path")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(ExtractError::invalid_link(
                member.position,
                member.path.to_path_buf(),
                target_text,
                reason,
            ));
        }
        let parent = self.ensure_parents(&member.path).await?;
        let entry = self.entries.ensure_child(parent, leaf_name(&member.path));
        self.replace_leaf(&member.path, entry, parent).await?;
        self.with_root("create hard link", &member.path, move |directory, path| {
            directory.hard_link(target.as_path(), directory, path)
        })
        .await?;
        self.entries.set_state(entry, ExtractedEntry::File);
        // The new path and target now share an inode. Writing through either
        // name updates both while preserving the hard-link relationship.
        if size == 0 {
            payload.skip().await.map_err(ExtractError::Archive)?;
            Ok(())
        } else {
            let file = self
                .open_file(
                    "truncate file",
                    &member.path,
                    parent,
                    FileOpenMode::Truncate,
                )
                .await?;
            write_payload(payload, chunk_buffer, &member.path, file).await
        }
    }

    /// Validates active symbolic links against the complete graph, then creates them.
    pub(super) async fn finalize_symlinks(
        &mut self,
        policy: LinkPolicy,
    ) -> Result<(), ExtractError<E>> {
        let mut links = Vec::with_capacity(self.symlinks.len());
        let mut resolution_work_bytes = 0;
        for (index, link) in self.symlinks.iter().enumerate() {
            if self.entries.state(link.entry) != Some(ExtractedEntry::Symlink { index }) {
                continue;
            }
            let target = self
                .resolve_terminal(&link.resolved_target, &mut resolution_work_bytes)
                .map_err(|reason| link.error(reason))?;
            let kind = match target {
                ResolvedTarget::Known(kind) => kind,
                ResolvedTarget::Unowned(_)
                    if !policy.allow_ambient_targets && !policy.allow_missing_targets =>
                {
                    return Err(link.error("target was not created by this extraction"));
                }
                ResolvedTarget::Unowned(path) => {
                    let (kind, traverses_ambient_link) = self.inspect_ambient_target(&path).await?;
                    if traverses_ambient_link && !policy.allow_ambient_targets {
                        return Err(link.error("ambient target is not allowed"));
                    }
                    match kind {
                        TerminalKind::Directory | TerminalKind::NonDirectory
                            if !policy.allow_ambient_targets =>
                        {
                            return Err(link.error("ambient target is not allowed"));
                        }
                        _ => {}
                    }
                    kind
                }
            };
            if kind == TerminalKind::Dangling && !policy.allow_missing_targets {
                return Err(link.error("target does not exist"));
            }
            if kind == TerminalKind::NonDirectory && link.requires_directory {
                return Err(link.error("target path suffix requires a directory"));
            }
            links.push(index);
        }

        for index in links {
            let (entry, parent, path, contents) = {
                let link = &self.symlinks[index];
                (
                    link.entry,
                    link.parent,
                    link.path.clone(),
                    link.target.clone(),
                )
            };
            match self
                .try_create_symlink(&path, parent, contents.clone())
                .await?
            {
                Ok(()) => continue,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(ExtractError::filesystem(
                        "create symbolic link",
                        path.to_path_buf(),
                        source,
                    ));
                }
            }

            // Distinct archive paths can name the same filesystem leaf through
            // case folding or Unicode normalization. Reservation flushes files
            // and removes existing leaves, so a non-link found here belongs to
            // a later archive member and already has precedence. A link can be
            // an earlier deferred link, which this member may replace according
            // to the normal overwrite policy.
            self.check_replacement(&path, entry)?;
            if let Some(metadata) = self.metadata(&path, parent).await? {
                if !metadata_is_link(&metadata) {
                    continue;
                }
                self.remove_leaf(&path, entry, parent, &metadata).await?;
            }
            self.try_create_symlink(&path, parent, contents)
                .await?
                .map_err(|source| {
                    ExtractError::filesystem("create symbolic link", path.to_path_buf(), source)
                })?;
        }
        Ok(())
    }
}

// Destination state transitions and replacement policy.
impl<E> ExtractionRoot<E> {
    /// Queues a fully validated payload for ordered creation in a bounded batch.
    async fn queue_buffered_file(
        &mut self,
        path: &NormalizedPath,
        executable: bool,
        contents: Vec<u8>,
    ) -> Result<Vec<u8>, ExtractError<E>> {
        let parent = if let Some(parent) = self.known_parent(path) {
            parent
        } else {
            self.flush_buffered_files().await?;
            self.ensure_parents(path).await?
        };
        let entry = self.entries.ensure_child(parent, leaf_name(path));
        if matches!(
            self.entries.state(entry),
            Some(ExtractedEntry::Symlink { .. })
        ) {
            self.flush_buffered_files().await?;
            self.replace_leaf(path, entry, parent).await?;
        }
        if !self.buffered_files.is_empty()
            && self.buffered_file_bytes.saturating_add(contents.len())
                > BUFFERED_FILE_BATCH_MAX_BYTES
        {
            self.flush_buffered_files().await?;
        }
        let replacement = if !self.can_replace(entry) {
            BufferedFileReplacement::Disallowed
        } else if self.entries.state(entry) == Some(ExtractedEntry::File) {
            BufferedFileReplacement::ExpectedFile
        } else {
            BufferedFileReplacement::Allowed
        };
        if self
            .directory_handle
            .as_ref()
            .is_some_and(|(cached_entry, _)| *cached_entry == entry)
        {
            self.directory_handle = None;
        }
        let (directory, relative_path) = self.entry_capability(path, parent);
        self.buffered_file_bytes = self.buffered_file_bytes.saturating_add(contents.len());
        self.buffered_files.push(BufferedFile {
            directory,
            relative_path,
            error_path: path.to_path_buf(),
            executable,
            contents,
            replacement,
        });
        self.entries.set_state(entry, ExtractedEntry::File);
        if self.buffered_files.len() >= BUFFERED_FILE_BATCH_MAX_ENTRIES
            || self.buffered_file_bytes >= BUFFERED_FILE_BATCH_MAX_BYTES
        {
            self.flush_buffered_files().await?;
        }
        if let Some(buffer) = self.buffered_file_buffers.pop() {
            Ok(buffer)
        } else {
            Ok(Vec::new())
        }
    }

    pub(super) async fn flush_buffered_files(&mut self) -> Result<(), ExtractError<E>> {
        if self.buffered_files.is_empty() {
            return Ok(());
        }
        self.buffered_file_bytes = 0;
        let files = mem::take(&mut self.buffered_files);
        let cancellation = Arc::clone(&self.buffered_file_cancellation);
        let result =
            tokio::task::spawn_blocking(move || write_buffered_files(files, &cancellation))
                .await
                .map_err(ExtractError::<E>::BlockingTask)?;
        for mut buffer in result.buffers {
            buffer.clear();
            self.buffered_file_buffers.push(buffer);
        }
        if let Some((path, error)) = result.error {
            return Err(error.into_extract(&path));
        }
        Ok(())
    }

    fn known_parent(&self, path: &NormalizedPath) -> Option<EntryId> {
        self.entries.find_parent_directory(path)
    }

    async fn create_file(
        &mut self,
        path: &NormalizedPath,
        executable: bool,
    ) -> Result<File, ExtractError<E>> {
        let parent = self.ensure_parents(path).await?;
        let entry = self.entries.ensure_child(parent, leaf_name(path));
        if matches!(
            self.entries.state(entry),
            Some(ExtractedEntry::Symlink { .. })
        ) {
            self.replace_leaf(path, entry, parent).await?;
        }
        let file = match self
            .open_file(
                "create file",
                path,
                parent,
                FileOpenMode::CreateNew { executable },
            )
            .await
        {
            Ok(file) => file,
            Err(error) => {
                if !self.replace_leaf(path, entry, parent).await? {
                    return Err(error);
                }
                self.open_file(
                    "create file",
                    path,
                    parent,
                    FileOpenMode::CreateNew { executable },
                )
                .await?
            }
        };
        self.entries.set_state(entry, ExtractedEntry::File);
        Ok(file)
    }

    async fn ensure_parents(&mut self, path: &NormalizedPath) -> Result<EntryId, ExtractError<E>> {
        let mut current = NormalizedPath::default();
        let mut parent_entry = ROOT_ENTRY;
        for component in path.parent_components() {
            current.push(component);
            let entry = self.entries.ensure_child(parent_entry, component);
            self.ensure_directory(
                &current,
                entry,
                parent_entry,
                DirectoryPurpose::ImplicitParent,
            )
            .await?;
            parent_entry = entry;
        }
        Ok(parent_entry)
    }

    async fn ensure_directory(
        &mut self,
        path: &NormalizedPath,
        entry: EntryId,
        parent: EntryId,
        purpose: DirectoryPurpose,
    ) -> Result<(), ExtractError<E>> {
        if self
            .entries
            .state(entry)
            .is_some_and(ExtractedEntry::is_directory)
        {
            return Ok(());
        }
        if self.entries.state(entry).is_some() {
            if purpose == DirectoryPurpose::ImplicitParent {
                return Err(ExtractError::<E>::PathCollision {
                    path: path.to_path_buf(),
                });
            }
            self.replace_leaf(path, entry, parent).await?;
        }
        // Missing parents are common, so inspect and replace only after a collision.
        let create_error = match self.try_create_directory(path, parent).await? {
            Ok(directory) => {
                self.directory_handle = Some((entry, Arc::new(directory)));
                self.entries
                    .set_state(entry, ExtractedEntry::CreatedDirectory);
                return Ok(());
            }
            Err(error) => error,
        };
        let metadata = self.metadata(path, parent).await?;
        if metadata
            .as_ref()
            .is_some_and(|metadata| metadata.is_dir() && !metadata_is_link(metadata))
        {
            let directory = self
                .with_entry_parent("open directory", path, parent, |directory, path| {
                    directory.open_dir(path)
                })
                .await?;
            self.directory_handle = Some((entry, Arc::new(directory)));
            self.entries
                .set_state(entry, ExtractedEntry::AmbientDirectory);
            return Ok(());
        }
        if metadata.is_none() && self.entries.state(entry).is_none() {
            return Err(ExtractError::filesystem(
                "create directory",
                path.to_path_buf(),
                create_error,
            ));
        }
        if purpose == DirectoryPurpose::ImplicitParent {
            return Err(ExtractError::<E>::PathCollision {
                path: path.to_path_buf(),
            });
        }
        self.replace_leaf(path, entry, parent).await?;
        let directory = self.create_directory(path, parent).await?;
        self.directory_handle = Some((entry, Arc::new(directory)));
        self.entries
            .set_state(entry, ExtractedEntry::CreatedDirectory);
        Ok(())
    }

    async fn replace_leaf(
        &mut self,
        path: &NormalizedPath,
        entry: EntryId,
        parent: EntryId,
    ) -> Result<bool, ExtractError<E>> {
        let metadata = self.metadata(path, parent).await?;
        if metadata.is_none() && self.entries.state(entry).is_none() {
            return Ok(false);
        }
        self.check_replacement(path, entry)?;
        if let Some(metadata) = metadata {
            self.remove_leaf(path, entry, parent, &metadata).await?;
        }
        self.entries.clear_state(entry);
        Ok(true)
    }

    fn check_replacement(
        &self,
        path: &NormalizedPath,
        entry: EntryId,
    ) -> Result<(), ExtractError<E>> {
        if !self.can_replace(entry) {
            return Err(ExtractError::<E>::PathCollision {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    fn can_replace(&self, entry: EntryId) -> bool {
        self.allow_overwrites && !self.entries.has_active_children(entry)
    }
}

// Symbolic-link graph resolution.
impl<E> ExtractionRoot<E> {
    fn resolve_terminal(
        &self,
        path: &NormalizedPath,
        resolution_work_bytes: &mut usize,
    ) -> Result<ResolvedTarget, &'static str> {
        let mut path = Cow::Borrowed(path);
        let mut visited = HashSet::new();
        for _ in 0..=MAX_SYMLINK_EXPANSIONS {
            check_symlink_resolution_limit(resolution_work_bytes, &path)?;
            if !visited.insert(path.as_ref().clone()) {
                return Err("symbolic-link target cycle");
            }
            let mut components = path.components().peekable();
            let mut entry = Some(ROOT_ENTRY);
            let mut rewritten = None;
            while let Some(component) = components.next() {
                entry = entry.and_then(|parent| self.entries.child(parent, component));
                if let Some(entry) = entry {
                    match self.entries.state(entry) {
                        Some(ExtractedEntry::Symlink { index }) => {
                            if let Some(link) = self.symlinks.get(index) {
                                let mut target = link.resolved_target.clone();
                                target.extend(components.by_ref());
                                rewritten = Some(target);
                                break;
                            }
                        }
                        Some(ExtractedEntry::File) if components.peek().is_some() => {
                            return Ok(ResolvedTarget::Known(TerminalKind::Dangling));
                        }
                        _ => {}
                    }
                }
            }
            drop(components);
            if let Some(rewritten) = rewritten {
                path = Cow::Owned(rewritten);
            } else {
                if path.is_empty() {
                    return Ok(ResolvedTarget::Known(TerminalKind::Directory));
                }
                return Ok(match entry.and_then(|entry| self.entries.state(entry)) {
                    Some(ExtractedEntry::CreatedDirectory) => {
                        ResolvedTarget::Known(TerminalKind::Directory)
                    }
                    Some(ExtractedEntry::File) => ResolvedTarget::Known(TerminalKind::NonDirectory),
                    Some(ExtractedEntry::Symlink { .. }) => continue,
                    Some(ExtractedEntry::AmbientDirectory) | None => {
                        ResolvedTarget::Unowned(path.into_owned())
                    }
                });
            }
        }
        Err("symbolic-link target expansion limit exceeded")
    }

    async fn inspect_ambient_target(
        &self,
        path: &NormalizedPath,
    ) -> Result<(TerminalKind, bool), ExtractError<E>> {
        self.with_root("inspect symbolic-link target", path, |directory, path| {
            if path.as_os_str().is_empty() {
                return Ok((TerminalKind::Directory, false));
            }
            let kind = match directory.metadata(path) {
                Ok(metadata) if metadata.is_dir() => Ok(TerminalKind::Directory),
                Ok(_) => Ok(TerminalKind::NonDirectory),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(TerminalKind::Dangling),
                Err(error) => Err(error),
            }?;
            if kind != TerminalKind::Dangling {
                return Ok((kind, false));
            }

            let mut prefix = PathBuf::new();
            for component in path.components() {
                prefix.push(component.as_os_str());
                match directory.symlink_metadata(&prefix) {
                    Ok(metadata) if metadata_is_link(&metadata) => return Ok((kind, true)),
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                    Err(error) => return Err(error),
                }
            }
            Ok((kind, false))
        })
        .await
    }
}

// Capability-relative filesystem access.
impl<E> ExtractionRoot<E> {
    async fn metadata(
        &self,
        path: &NormalizedPath,
        parent: EntryId,
    ) -> Result<Option<Metadata>, ExtractError<E>> {
        self.with_entry_parent("inspect", path, parent, |directory, path| {
            match directory.symlink_metadata(path) {
                Ok(metadata) => Ok(Some(metadata)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        })
        .await
    }

    async fn remove_leaf(
        &mut self,
        path: &NormalizedPath,
        entry: EntryId,
        parent: EntryId,
        metadata: &Metadata,
    ) -> Result<(), ExtractError<E>> {
        if metadata.is_dir() && !metadata_is_link(metadata) {
            let is_empty = self
                .with_entry_parent("inspect directory", path, parent, directory_is_empty)
                .await?;
            if !is_empty {
                return Err(ExtractError::<E>::PathCollision {
                    path: path.to_path_buf(),
                });
            }
            // Windows directory handles do not share delete access.
            if self
                .directory_handle
                .as_ref()
                .is_some_and(|(cached_entry, _)| *cached_entry == entry)
            {
                self.directory_handle = None;
            }
            self.with_entry_parent("remove directory", path, parent, |directory, path| {
                directory.remove_dir(path)
            })
            .await
        } else {
            let is_link = metadata_is_link(metadata);
            self.with_entry_parent("remove file", path, parent, move |directory, path| {
                remove_file_or_symlink(directory, path, is_link)
            })
            .await
        }
    }

    async fn open_file(
        &self,
        operation: &'static str,
        path: &NormalizedPath,
        parent: EntryId,
        mode: FileOpenMode,
    ) -> Result<File, ExtractError<E>> {
        let file = self
            .with_entry_parent(operation, path, parent, move |directory, path| {
                let options = mode.options();
                directory
                    .open_with(path, &options)
                    .map(|file| file.into_std())
            })
            .await?;
        let mut file = File::from_std(file);
        // Keep each extraction chunk to one Tokio blocking write.
        file.set_max_buf_size(STREAMING_PAYLOAD_CHUNK_BYTES);
        Ok(file)
    }

    async fn create_directory(
        &self,
        path: &NormalizedPath,
        parent: EntryId,
    ) -> Result<Dir, ExtractError<E>> {
        self.try_create_directory(path, parent)
            .await?
            .map_err(|source| {
                ExtractError::filesystem("create directory", path.to_path_buf(), source)
            })
    }

    /// Attempts symbolic-link creation without attaching a path to an expected
    /// physical-filesystem collision.
    async fn try_create_symlink(
        &self,
        path: &NormalizedPath,
        parent: EntryId,
        contents: String,
    ) -> Result<io::Result<()>, ExtractError<E>> {
        let (directory, relative_path) = self.entry_capability(path, parent);
        run_blocking_io(directory, relative_path, move |directory, path| {
            create_symlink(directory, &contents, path)
        })
        .await
    }

    /// Attempts a directory creation without eagerly materializing its diagnostic path.
    ///
    /// An `AlreadyExists` result is expected while discovering ambient parents. Keeping
    /// that error pathless avoids copying every growing prefix before it is discarded.
    async fn try_create_directory(
        &self,
        path: &NormalizedPath,
        parent: EntryId,
    ) -> Result<io::Result<Dir>, ExtractError<E>> {
        let (directory, relative_path) = self.entry_capability(path, parent);
        run_blocking_io(directory, relative_path, |directory, path| {
            directory.create_dir(path)?;
            directory.open_dir(path)
        })
        .await
    }

    /// Runs an operation against the root capability with the full relative path.
    async fn with_root<T, F>(
        &self,
        operation: &'static str,
        path: &NormalizedPath,
        action: F,
    ) -> Result<T, ExtractError<E>>
    where
        T: Send + 'static,
        F: FnOnce(&Dir, &Path) -> io::Result<T> + Send + 'static,
    {
        run_blocking(
            Arc::clone(&self.directory),
            operation,
            path,
            path.to_path_buf(),
            action,
        )
        .await
    }

    /// Runs an operation against the nearest cached parent capability.
    ///
    /// `action` receives only the leaf when its parent is cached; diagnostics
    /// retain the complete root-relative path.
    async fn with_entry_parent<T, F>(
        &self,
        operation: &'static str,
        path: &NormalizedPath,
        parent: EntryId,
        action: F,
    ) -> Result<T, ExtractError<E>>
    where
        T: Send + 'static,
        F: FnOnce(&Dir, &Path) -> io::Result<T> + Send + 'static,
    {
        let (directory, relative_path) = self.entry_capability(path, parent);
        run_blocking(directory, operation, path, relative_path, action).await
    }

    fn entry_capability(&self, path: &NormalizedPath, parent: EntryId) -> (Arc<Dir>, PathBuf) {
        if let Some(file_name) = path.file_name() {
            if parent == ROOT_ENTRY {
                return (Arc::clone(&self.directory), file_name.into());
            }
            if let Some((cached_entry, directory)) = &self.directory_handle
                && *cached_entry == parent
            {
                return (Arc::clone(directory), file_name.into());
            }
        }
        (Arc::clone(&self.directory), path.to_path_buf())
    }
}

fn check_symlink_resolution_limit(
    resolution_work_bytes: &mut usize,
    path: &NormalizedPath,
) -> Result<(), &'static str> {
    let mut prefix_bytes = 0usize;
    let mut work_bytes = path
        .as_str()
        .len()
        .checked_mul(2)
        .ok_or(SYMLINK_RESOLUTION_LIMIT_EXCEEDED)?;
    for component in path.components() {
        prefix_bytes = prefix_bytes
            .checked_add(component.len())
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or(SYMLINK_RESOLUTION_LIMIT_EXCEEDED)?;
        work_bytes = work_bytes
            .checked_add(prefix_bytes)
            .ok_or(SYMLINK_RESOLUTION_LIMIT_EXCEEDED)?;
    }
    *resolution_work_bytes = resolution_work_bytes
        .checked_add(work_bytes)
        .filter(|bytes| *bytes <= MAX_SYMLINK_RESOLUTION_WORK_BYTES)
        .ok_or(SYMLINK_RESOLUTION_LIMIT_EXCEEDED)?;
    Ok(())
}

fn leaf_name(path: &NormalizedPath) -> &str {
    if let Some(file_name) = path.file_name() {
        file_name
    } else {
        path.as_str()
    }
}

fn directory_is_empty(directory: &Dir, path: &Path) -> io::Result<bool> {
    let directory = directory.open_dir(path)?;
    let mut entries = directory.entries()?;
    Ok(entries.next().transpose()?.is_none())
}

#[cfg(not(windows))]
fn remove_file_or_symlink(directory: &Dir, path: &Path, _is_link: bool) -> io::Result<()> {
    directory.remove_file(path)
}

#[cfg(windows)]
fn remove_file_or_symlink(directory: &Dir, path: &Path, is_link: bool) -> io::Result<()> {
    if is_link {
        // Stable Windows does not expose whether a symlink is file- or
        // directory-shaped.
        return directory
            .remove_file(path)
            .or_else(|_| directory.remove_dir(path));
    }
    directory.remove_file(path)
}

/// Runs one capability-relative filesystem operation on Tokio's blocking pool.
///
/// `relative_path` is passed to `action`; `error_path` is retained only for
/// [`ExtractError::Filesystem`] diagnostics.
async fn run_blocking<E, T, F>(
    directory: Arc<Dir>,
    operation: &'static str,
    error_path: &NormalizedPath,
    relative_path: PathBuf,
    action: F,
) -> Result<T, ExtractError<E>>
where
    T: Send + 'static,
    F: FnOnce(&Dir, &Path) -> io::Result<T> + Send + 'static,
{
    run_blocking_io(directory, relative_path, action)
        .await?
        .map_err(|source| ExtractError::filesystem(operation, error_path.to_path_buf(), source))
}

/// Runs one capability-relative filesystem operation without attaching a path to I/O errors.
async fn run_blocking_io<E, T, F>(
    directory: Arc<Dir>,
    relative_path: PathBuf,
    action: F,
) -> Result<io::Result<T>, ExtractError<E>>
where
    T: Send + 'static,
    F: FnOnce(&Dir, &Path) -> io::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || action(&directory, &relative_path))
        .await
        .map_err(ExtractError::<E>::BlockingTask)
}

#[cfg(not(windows))]
fn ambient_metadata_is_link(metadata: &std_fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn ambient_metadata_is_link(metadata: &std_fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_link(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn metadata_is_link(metadata: &Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(unix)]
fn create_symlink(directory: &Dir, contents: &str, path: &Path) -> io::Result<()> {
    directory.symlink(contents, path)
}

#[cfg(not(unix))]
fn create_symlink(_directory: &Dir, _contents: &str, _path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symbolic links are not supported on this platform",
    ))
}
