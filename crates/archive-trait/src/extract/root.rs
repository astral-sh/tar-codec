//! Destination state and capability-relative filesystem operations.
//!
//! [`ExtractionRoot`] records archive-owned paths and anchors mutations beneath
//! one verified directory capability.

mod buffered;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
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
    path::{ExtractMember, resolve_link_target, validate_symlink_target},
};
use crate::{ExtractError, MemberPayload};

/// A symbolic link reserved until the completed archive graph can be validated.
#[derive(Debug)]
struct PendingSymlink {
    path: PathBuf,
    position: u64,
    target: String,
    resolved_target: PathBuf,
    requires_directory: bool,
}

impl PendingSymlink {
    fn error<E>(&self, reason: &'static str) -> ExtractError<E> {
        ExtractError::invalid_link(
            self.position,
            self.path.clone(),
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
    Symlink,
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
    directory_handle: Option<(PathBuf, Arc<Dir>)>,
    /// Whether overwrites are allowed during extraction.
    allow_overwrites: bool,
    /// The latest state recorded for every path encountered by the extraction.
    entries: HashMap<PathBuf, ExtractedEntry>,
    /// The active pending symbolic link at each reserved path.
    symlink_indices: HashMap<PathBuf, usize>,
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
    Unowned(PathBuf),
}

/// Streams a large payload into an already-created file.
async fn write_payload<P: MemberPayload>(
    mut payload: P,
    chunk_buffer: &mut Vec<u8>,
    path: &Path,
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
            .map_err(|source| ExtractError::filesystem("write file", path.to_owned(), source))?;
    }
    file.flush()
        .await
        .map_err(|source| ExtractError::filesystem("flush file", path.to_owned(), source))?;
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
            entries: HashMap::new(),
            symlink_indices: HashMap::new(),
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
        path: &Path,
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
    pub(super) async fn extract_directory(&mut self, path: &Path) -> Result<(), ExtractError<E>> {
        self.flush_buffered_files().await?;
        if !path.as_os_str().is_empty() {
            self.ensure_parents(path).await?;
            self.ensure_directory(path, DirectoryPurpose::ExplicitMember)
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
        self.ensure_parents(&member.path).await?;
        self.replace_leaf(&member.path).await?;
        let path = member.path.clone();
        self.entries.insert(path.clone(), ExtractedEntry::Symlink);
        self.symlink_indices
            .insert(path.clone(), self.symlinks.len());
        self.symlinks.push(PendingSymlink {
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
            Path::new(""),
        )?;
        let reason = if !matches!(self.entries.get(&target), Some(ExtractedEntry::File)) {
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
                member.path.clone(),
                target_text,
                reason,
            ));
        }
        self.ensure_parents(&member.path).await?;
        self.replace_leaf(&member.path).await?;
        self.with_root("create hard link", &member.path, move |directory, path| {
            directory.hard_link(target, directory, path)
        })
        .await?;
        self.entries
            .insert(member.path.clone(), ExtractedEntry::File);
        // The new path and target now share an inode. Writing through either
        // name updates both while preserving the hard-link relationship.
        if size == 0 {
            payload.skip().await.map_err(ExtractError::Archive)?;
            Ok(())
        } else {
            let file = self
                .open_file("truncate file", &member.path, FileOpenMode::Truncate)
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
            if self.symlink_indices.get(&link.path) != Some(&index) {
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
            let link = &self.symlinks[index];
            let contents = link.target.clone();
            self.with_entry_parent(
                "create symbolic link",
                &link.path,
                move |directory, path| create_symlink(directory, &contents, path),
            )
            .await?;
        }
        Ok(())
    }
}

// Destination state transitions and replacement policy.
impl<E> ExtractionRoot<E> {
    /// Queues a fully validated payload for ordered creation in a bounded batch.
    async fn queue_buffered_file(
        &mut self,
        path: &Path,
        executable: bool,
        contents: Vec<u8>,
    ) -> Result<Vec<u8>, ExtractError<E>> {
        if !self.parents_are_known(path) {
            self.flush_buffered_files().await?;
            self.ensure_parents(path).await?;
        }
        if self.symlink_indices.contains_key(path) {
            self.flush_buffered_files().await?;
            self.replace_leaf(path).await?;
        }
        if !self.buffered_files.is_empty()
            && self.buffered_file_bytes.saturating_add(contents.len())
                > BUFFERED_FILE_BATCH_MAX_BYTES
        {
            self.flush_buffered_files().await?;
        }
        let replacement = if !self.can_replace(path) {
            BufferedFileReplacement::Disallowed
        } else if matches!(self.entries.get(path), Some(ExtractedEntry::File)) {
            BufferedFileReplacement::ExpectedFile
        } else {
            BufferedFileReplacement::Allowed
        };
        if self
            .directory_handle
            .as_ref()
            .is_some_and(|(cached_path, _)| cached_path == path)
        {
            self.directory_handle = None;
        }
        let (directory, relative_path) = self.entry_capability(path);
        self.buffered_file_bytes = self.buffered_file_bytes.saturating_add(contents.len());
        self.buffered_files.push(BufferedFile {
            directory,
            relative_path,
            error_path: path.to_owned(),
            executable,
            contents,
            replacement,
        });
        self.entries.insert(path.to_owned(), ExtractedEntry::File);
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

    fn parents_are_known(&self, path: &Path) -> bool {
        let Some(parent) = path.parent() else {
            return true;
        };
        let mut current = PathBuf::new();
        for component in parent.components() {
            current.push(component.as_os_str());
            if !matches!(
                self.entries.get(&current),
                Some(ExtractedEntry::CreatedDirectory | ExtractedEntry::AmbientDirectory)
            ) {
                return false;
            }
        }
        true
    }

    async fn create_file(
        &mut self,
        path: &Path,
        executable: bool,
    ) -> Result<File, ExtractError<E>> {
        self.ensure_parents(path).await?;
        if self.symlink_indices.contains_key(path) {
            self.replace_leaf(path).await?;
        }
        let file = match self
            .open_file("create file", path, FileOpenMode::CreateNew { executable })
            .await
        {
            Ok(file) => file,
            Err(error) => {
                if !self.replace_leaf(path).await? {
                    return Err(error);
                }
                self.open_file("create file", path, FileOpenMode::CreateNew { executable })
                    .await?
            }
        };
        self.entries.insert(path.to_owned(), ExtractedEntry::File);
        Ok(file)
    }

    async fn ensure_parents(&mut self, path: &Path) -> Result<(), ExtractError<E>> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        let mut current = PathBuf::new();
        for component in parent.components() {
            current.push(component.as_os_str());
            self.ensure_directory(&current, DirectoryPurpose::ImplicitParent)
                .await?;
        }
        Ok(())
    }

    async fn ensure_directory(
        &mut self,
        path: &Path,
        purpose: DirectoryPurpose,
    ) -> Result<(), ExtractError<E>> {
        if matches!(
            self.entries.get(path),
            Some(ExtractedEntry::CreatedDirectory | ExtractedEntry::AmbientDirectory)
        ) {
            return Ok(());
        }
        if self.entries.contains_key(path) {
            if purpose == DirectoryPurpose::ImplicitParent {
                return Err(ExtractError::<E>::PathCollision {
                    path: path.to_owned(),
                });
            }
            self.replace_leaf(path).await?;
        }
        // Missing parents are common, so inspect and replace only after a collision.
        let create_error = match self.create_directory(path).await {
            Ok(directory) => {
                self.directory_handle = Some((path.to_owned(), Arc::new(directory)));
                self.entries
                    .insert(path.to_owned(), ExtractedEntry::CreatedDirectory);
                return Ok(());
            }
            Err(error) => error,
        };
        let metadata = self.metadata(path).await?;
        if metadata
            .as_ref()
            .is_some_and(|metadata| metadata.is_dir() && !metadata_is_link(metadata))
        {
            let directory = self
                .with_entry_parent("open directory", path, |directory, path| {
                    directory.open_dir(path)
                })
                .await?;
            self.directory_handle = Some((path.to_owned(), Arc::new(directory)));
            self.entries
                .insert(path.to_owned(), ExtractedEntry::AmbientDirectory);
            return Ok(());
        }
        if metadata.is_none() && !self.entries.contains_key(path) {
            return Err(create_error);
        }
        if purpose == DirectoryPurpose::ImplicitParent {
            return Err(ExtractError::<E>::PathCollision {
                path: path.to_owned(),
            });
        }
        self.replace_leaf(path).await?;
        let directory = self.create_directory(path).await?;
        self.directory_handle = Some((path.to_owned(), Arc::new(directory)));
        self.entries
            .insert(path.to_owned(), ExtractedEntry::CreatedDirectory);
        Ok(())
    }

    async fn replace_leaf(&mut self, path: &Path) -> Result<bool, ExtractError<E>> {
        let metadata = self.metadata(path).await?;
        if metadata.is_none() && !self.entries.contains_key(path) {
            return Ok(false);
        }
        self.check_replacement(path)?;
        if let Some(metadata) = metadata {
            self.remove_leaf(path, &metadata).await?;
        }
        self.entries.remove(path);
        self.symlink_indices.remove(path);
        Ok(true)
    }

    fn check_replacement(&self, path: &Path) -> Result<(), ExtractError<E>> {
        if !self.can_replace(path) {
            return Err(ExtractError::<E>::PathCollision {
                path: path.to_owned(),
            });
        }
        Ok(())
    }

    fn can_replace(&self, path: &Path) -> bool {
        if !self.allow_overwrites {
            return false;
        }
        // Every extracted descendant records its parent directory, while files
        // and links cannot own descendants. Only known directories need a scan.
        if !matches!(
            self.entries.get(path),
            Some(ExtractedEntry::CreatedDirectory | ExtractedEntry::AmbientDirectory)
        ) {
            return true;
        }
        !self
            .entries
            .keys()
            .any(|candidate| candidate != path && candidate.starts_with(path))
    }
}

// Symbolic-link graph resolution.
impl<E> ExtractionRoot<E> {
    fn resolve_terminal(
        &self,
        path: &Path,
        resolution_work_bytes: &mut usize,
    ) -> Result<ResolvedTarget, &'static str> {
        let mut path = Cow::Borrowed(path);
        let mut visited = HashSet::new();
        for _ in 0..=MAX_SYMLINK_EXPANSIONS {
            check_symlink_resolution_limit(resolution_work_bytes, &path)?;
            if !visited.insert(path.to_path_buf()) {
                return Err("symbolic-link target cycle");
            }
            let mut components = path.components().peekable();
            let mut prefix = PathBuf::new();
            let mut rewritten = None;
            while let Some(component) = components.next() {
                prefix.push(component.as_os_str());
                if let Some(link_index) = self.symlink_indices.get(&prefix)
                    && let Some(link) = self.symlinks.get(*link_index)
                {
                    let mut target = link.resolved_target.clone();
                    target.extend(components.by_ref().map(|component| component.as_os_str()));
                    rewritten = Some(target);
                    break;
                }
                if components.peek().is_some()
                    && matches!(self.entries.get(&prefix), Some(ExtractedEntry::File))
                {
                    return Ok(ResolvedTarget::Known(TerminalKind::Dangling));
                }
            }
            if let Some(rewritten) = rewritten {
                path = Cow::Owned(rewritten);
            } else {
                if path.as_os_str().is_empty() {
                    return Ok(ResolvedTarget::Known(TerminalKind::Directory));
                }
                return Ok(match self.entries.get(path.as_ref()).copied() {
                    Some(ExtractedEntry::CreatedDirectory) => {
                        ResolvedTarget::Known(TerminalKind::Directory)
                    }
                    Some(ExtractedEntry::File) => ResolvedTarget::Known(TerminalKind::NonDirectory),
                    Some(ExtractedEntry::Symlink) => continue,
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
        path: &Path,
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
    async fn metadata(&self, path: &Path) -> Result<Option<Metadata>, ExtractError<E>> {
        self.with_entry_parent("inspect", path, |directory, path| {
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
        path: &Path,
        metadata: &Metadata,
    ) -> Result<(), ExtractError<E>> {
        if metadata.is_dir() && !metadata_is_link(metadata) {
            let is_empty = self
                .with_entry_parent("inspect directory", path, directory_is_empty)
                .await?;
            if !is_empty {
                return Err(ExtractError::<E>::PathCollision {
                    path: path.to_owned(),
                });
            }
            // Windows directory handles do not share delete access.
            if self
                .directory_handle
                .as_ref()
                .is_some_and(|(cached_path, _)| cached_path == path)
            {
                self.directory_handle = None;
            }
            self.with_entry_parent("remove directory", path, |directory, path| {
                directory.remove_dir(path)
            })
            .await
        } else {
            let is_link = metadata_is_link(metadata);
            self.with_entry_parent("remove file", path, move |directory, path| {
                remove_file_or_symlink(directory, path, is_link)
            })
            .await
        }
    }

    async fn open_file(
        &self,
        operation: &'static str,
        path: &Path,
        mode: FileOpenMode,
    ) -> Result<File, ExtractError<E>> {
        let file = self
            .with_entry_parent(operation, path, move |directory, path| {
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

    async fn create_directory(&self, path: &Path) -> Result<Dir, ExtractError<E>> {
        self.with_entry_parent("create directory", path, |directory, path| {
            directory.create_dir(path)?;
            directory.open_dir(path)
        })
        .await
    }

    /// Runs an operation against the root capability with the full relative path.
    async fn with_root<T, F>(
        &self,
        operation: &'static str,
        path: &Path,
        action: F,
    ) -> Result<T, ExtractError<E>>
    where
        T: Send + 'static,
        F: FnOnce(&Dir, &Path) -> io::Result<T> + Send + 'static,
    {
        run_blocking(
            Arc::clone(&self.directory),
            operation,
            path.to_owned(),
            path.to_owned(),
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
        path: &Path,
        action: F,
    ) -> Result<T, ExtractError<E>>
    where
        T: Send + 'static,
        F: FnOnce(&Dir, &Path) -> io::Result<T> + Send + 'static,
    {
        let (directory, relative_path) = self.entry_capability(path);
        run_blocking(directory, operation, path.to_owned(), relative_path, action).await
    }

    fn entry_capability(&self, path: &Path) -> (Arc<Dir>, PathBuf) {
        if let Some(parent) = path.parent()
            && let Some(file_name) = path.file_name()
        {
            if parent.as_os_str().is_empty() {
                return (Arc::clone(&self.directory), file_name.into());
            }
            if let Some((cached_path, directory)) = &self.directory_handle
                && cached_path == parent
            {
                return (Arc::clone(directory), file_name.into());
            }
        }
        (Arc::clone(&self.directory), path.to_owned())
    }
}

fn check_symlink_resolution_limit(
    resolution_work_bytes: &mut usize,
    path: &Path,
) -> Result<(), &'static str> {
    let mut prefix_bytes = 0usize;
    let mut work_bytes = path
        .as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_mul(2)
        .ok_or(SYMLINK_RESOLUTION_LIMIT_EXCEEDED)?;
    for component in path.components() {
        prefix_bytes = prefix_bytes
            .checked_add(component.as_os_str().as_encoded_bytes().len())
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
    error_path: PathBuf,
    relative_path: PathBuf,
    action: F,
) -> Result<T, ExtractError<E>>
where
    T: Send + 'static,
    F: FnOnce(&Dir, &Path) -> io::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || action(&directory, &relative_path))
        .await
        .map_err(ExtractError::<E>::BlockingTask)?
        .map_err(|source| ExtractError::filesystem(operation, error_path, source))
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
