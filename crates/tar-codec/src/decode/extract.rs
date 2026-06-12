//! Filesystem extraction implementation and its private support types.

use std::{
    collections::{HashMap, HashSet},
    fs as std_fs,
    sync::Arc,
};

use super::*;
#[cfg(unix)]
use cap_std::fs::OpenOptionsExt as _;
use cap_std::{
    ambient_authority,
    fs::{Dir, Metadata, OpenOptions},
};
use tar_framing::logical::MemberPayload;
use tokio::{fs::File, io::AsyncWriteExt};
#[cfg(windows)]
use {
    cap_std::fs::MetadataExt as _, std::os::windows::fs::MetadataExt as _,
    windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT,
};

/// A symbolic link awaiting graph validation and filesystem installation.
///
/// [`PendingSymlink::link_contents`] is written to the filesystem, while
/// [`PendingSymlink::resolved_target`] is used to validate the archive's
/// symbolic-link graph relative to the extraction root.
#[derive(Clone, Debug)]
struct PendingSymlink {
    path: PathBuf,
    position: u64,
    target_text: String,
    link_contents: PathBuf,
    resolved_target: PathBuf,
    requires_directory: bool,
}

impl PendingSymlink {
    fn error(&self, reason: &'static str) -> DecodeError {
        DecodeError::invalid_link(
            self.position,
            self.path.clone(),
            self.target_text.clone(),
            reason,
        )
    }
}

// Keep graph validation bounded when each symbolic-link substitution grows the
// remaining path instead of revisiting an identical expansion.
const MAX_SYMLINK_EXPANSIONS: usize = 256;

// How big of a chunk to read from each member, at a time.
// This is also the limit for our single-read optimization; see below.
const EXTRACTION_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExtractedEntry {
    File,
    CreatedDirectory,
    AmbientDirectory,
    Symlink,
}

impl ExtractedEntry {
    fn is_directory(self) -> bool {
        matches!(self, Self::CreatedDirectory | Self::AmbientDirectory)
    }
}

/// Represents a root directory for an extraction operation.
struct ExtractionRoot {
    /// The capability anchoring all extraction filesystem operations.
    directory: Arc<Dir>,
    /// Capabilities for known directories, used to keep leaf operations cheap.
    directory_handles: HashMap<PathBuf, Arc<Dir>>,
    /// Whether overwrites are allowed during extraction.
    allow_overwrites: bool,
    entries: HashMap<PathBuf, ExtractedEntry>,
    symlink_indices: HashMap<PathBuf, usize>,
    symlinks: Vec<PendingSymlink>,
}

/// The filesystem shape of a fully resolved symbolic-link target.
///
/// This determines which kind of symbolic link to create on platforms such as
/// Windows, where file and directory symbolic links use different operations.
#[derive(Clone, Copy, Eq, PartialEq)]
enum TerminalKind {
    /// The target exists and is not a directory.
    File,
    /// The target exists and is a directory.
    Directory,
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

impl<R: AsyncRead + Unpin> Archive<R> {
    /// Securely extracts this archive beneath `dest` under `policy`.
    ///
    /// `dest` is created if it does not already exist.
    ///
    /// `policy` controls extraction semantics, including overwrite behavior.
    /// See [`DecodePolicy`] for information about each option and its default.
    ///
    /// Archived Unix permission modes are normalized rather than restored. New
    /// regular files are created with mode `0o777` when any archived execute bit
    /// is set and `0o666` otherwise, in both cases filtered by the process umask.
    /// Directories use the platform's default creation mode, and special mode
    /// bits are not restored. Callers extracting sensitive contents should
    /// pre-create `dest` and its ancestors with suitably restrictive permissions.
    ///
    /// **IMPORTANT**: `dest` **MUST NOT** be concurrently modified during extraction.
    /// No correctness/isolation guarantees are made if `dest` is externally modified.
    ///
    /// **IMPORTANT**: extraction occurs in a streamwise fashion, meaning that a late
    /// error can leave a partially extracted state under `dest`. Users that require
    /// "all or nothing" behavior should attempt extraction in a new temporary
    /// directory, and then atomically rename that directory to `dest`.
    pub async fn extract<P: AsRef<Path>>(
        mut self,
        dest: P,
        policy: DecodePolicy,
    ) -> Result<(), DecodeError> {
        self.reader
            .set_max_pax_extension_size(policy.pax_policy.max_extension_size);
        let mut root = ExtractionRoot::open(dest.as_ref(), policy.allow_overwrites).await?;
        let mut payload_chunk = Vec::new();
        while let Some(frame) = self.reader.next_frame().await? {
            policy.check_member(&frame)?;
            let member = decode_member(&frame, &policy)?;
            match member.kind {
                UstarKind::Regular | UstarKind::Contiguous => {
                    root.extract_file(&member, frame.payload, &mut payload_chunk)
                        .await?;
                }
                UstarKind::Directory => {
                    root.extract_directory(&member.path).await?;
                    frame.payload.skip().await?;
                }
                UstarKind::SymbolicLink => {
                    root.reserve_symlink(&member).await?;
                    frame.payload.skip().await?;
                }
                UstarKind::HardLink => {
                    root.extract_hard_link(&member, frame.payload, &mut payload_chunk)
                        .await?;
                }
                UstarKind::CharacterDevice | UstarKind::BlockDevice | UstarKind::Fifo => {
                    return Err(DecodeError::UnsupportedMember {
                        position: member.position,
                        path: member.path,
                        kind: member.kind,
                    });
                }
            }
        }
        root.install_symlinks(policy.symlink_target_policy).await
    }
}

async fn write_payload<R: AsyncRead + Unpin>(
    mut payload: MemberPayload<'_, R>,
    payload_chunk: &mut Vec<u8>,
    path: &Path,
    mut file: File,
) -> Result<(), DecodeError> {
    while payload
        .next_chunk(payload_chunk, EXTRACTION_CHUNK_BYTES)
        .await?
    {
        file.write_all(payload_chunk)
            .await
            .map_err(|source| DecodeError::filesystem("write file", path.to_owned(), source))?;
    }
    file.flush()
        .await
        .map_err(|source| DecodeError::filesystem("flush file", path.to_owned(), source))?;
    Ok(())
}

impl ExtractionRoot {
    async fn open(dest: &Path, allow_overwrites: bool) -> Result<Self, DecodeError> {
        let dest = dest.to_owned();
        let error_path = dest.clone();
        let directory = tokio::task::spawn_blocking(move || {
            match std_fs::symlink_metadata(&dest) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std_fs::create_dir_all(&dest)?;
                }
                Err(error) => return Err(error),
            }
            let metadata = std_fs::symlink_metadata(&dest)?;
            if ambient_metadata_is_link(&metadata) || !metadata.is_dir() {
                return Err(io::Error::other("destination is not a real directory"));
            }
            let path = std_fs::canonicalize(dest)?;
            let directory = Dir::open_ambient_dir(path, ambient_authority())?;
            let metadata = directory.dir_metadata()?;
            if metadata_is_link(&metadata) || !metadata.is_dir() {
                return Err(io::Error::other("destination is not a real directory"));
            }
            Ok(Arc::new(directory))
        })
        .await
        .map_err(DecodeError::BlockingTask)?
        .map_err(|source| {
            DecodeError::filesystem("open destination directory", error_path, source)
        })?;

        Ok(Self {
            directory,
            directory_handles: HashMap::new(),
            allow_overwrites,
            entries: HashMap::new(),
            symlink_indices: HashMap::new(),
            symlinks: Vec::new(),
        })
    }

    async fn extract_file<R: AsyncRead + Unpin>(
        &mut self,
        member: &DecodedMember,
        mut payload: MemberPayload<'_, R>,
        payload_chunk: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
        if member.effective_size <= EXTRACTION_CHUNK_BYTES as u64 {
            payload_chunk.clear();
            if member.effective_size != 0 {
                payload
                    .next_chunk(payload_chunk, EXTRACTION_CHUNK_BYTES)
                    .await?;
            }
            let mut file = self.create_file(&member.path, member.executable).await?;
            file.write_all(payload_chunk).await.map_err(|source| {
                DecodeError::filesystem("write file", member.path.clone(), source)
            })?;
            file.flush().await.map_err(|source| {
                DecodeError::filesystem("flush file", member.path.clone(), source)
            })?;
            return Ok(());
        }
        let file = self.create_file(&member.path, member.executable).await?;
        write_payload(payload, payload_chunk, &member.path, file).await
    }

    async fn extract_directory(&mut self, path: &Path) -> Result<(), DecodeError> {
        if !path.as_os_str().is_empty() {
            self.ensure_parents(path).await?;
            self.ensure_directory(path).await?;
        }
        Ok(())
    }

    async fn create_file(&mut self, path: &Path, executable: bool) -> Result<File, DecodeError> {
        self.ensure_parents(path).await?;
        if self.symlink_indices.contains_key(path) {
            self.replace_leaf(path).await?;
        }
        let file = match self
            .open_file("create file", path, true, false, executable)
            .await
        {
            Ok(file) => file,
            Err(error) => {
                if !self.replace_leaf(path).await? {
                    return Err(error);
                }
                self.open_file("create file", path, true, false, executable)
                    .await?
            }
        };
        self.entries.insert(path.to_owned(), ExtractedEntry::File);
        Ok(file)
    }

    async fn reserve_symlink(&mut self, member: &DecodedMember) -> Result<(), DecodeError> {
        let target_text = member.link_target.clone();
        let target = validate_symlink_target(member.position, &member.path, &target_text)?;
        self.ensure_parents(&member.path).await?;
        self.replace_leaf(&member.path).await?;
        let path = member.path.clone();
        self.entries.insert(path.clone(), ExtractedEntry::Symlink);
        self.symlink_indices
            .insert(path.clone(), self.symlinks.len());
        self.symlinks.push(PendingSymlink {
            path,
            position: member.position,
            target_text,
            link_contents: target.link_contents,
            resolved_target: target.resolved_target,
            requires_directory: target.requires_directory,
        });
        Ok(())
    }

    async fn extract_hard_link<R: AsyncRead + Unpin>(
        &mut self,
        member: &DecodedMember,
        payload: MemberPayload<'_, R>,
        payload_chunk: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
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
            return Err(DecodeError::invalid_link(
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
        if member.effective_size == 0 {
            payload.skip().await?;
            Ok(())
        } else {
            let file = self
                .open_file("truncate file", &member.path, false, true, false)
                .await?;
            write_payload(payload, payload_chunk, &member.path, file).await
        }
    }

    async fn ensure_parents(&mut self, path: &Path) -> Result<(), DecodeError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        let mut current = PathBuf::new();
        for component in parent.components() {
            current.push(component.as_os_str());
            self.ensure_directory(&current).await?;
        }
        Ok(())
    }

    async fn ensure_directory(&mut self, path: &Path) -> Result<(), DecodeError> {
        if let Some(entry) = self.entries.get(path).copied()
            && entry.is_directory()
        {
            return Ok(());
        }
        if self.entries.contains_key(path) {
            self.replace_leaf(path).await?;
        }
        // Missing parents are common, so inspect and replace only after a collision.
        let create_error = match self.create_directory(path).await {
            Ok(directory) => {
                self.directory_handles
                    .insert(path.to_owned(), Arc::new(directory));
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
            let directory = self.open_directory(path).await?;
            self.directory_handles
                .insert(path.to_owned(), Arc::new(directory));
            self.entries
                .insert(path.to_owned(), ExtractedEntry::AmbientDirectory);
            return Ok(());
        }
        if metadata.is_none() && !self.entries.contains_key(path) {
            return Err(create_error);
        }
        self.replace_leaf(path).await?;
        let directory = self.create_directory(path).await?;
        self.directory_handles
            .insert(path.to_owned(), Arc::new(directory));
        self.entries
            .insert(path.to_owned(), ExtractedEntry::CreatedDirectory);
        Ok(())
    }

    async fn replace_leaf(&mut self, path: &Path) -> Result<bool, DecodeError> {
        let metadata = self.metadata(path).await?;
        if metadata.is_none() && !self.entries.contains_key(path) {
            return Ok(false);
        }
        if !self.allow_overwrites || self.has_descendant(path) {
            return Err(DecodeError::PathCollision {
                path: path.to_owned(),
            });
        }
        if let Some(metadata) = metadata {
            self.remove_leaf(path, &metadata).await?;
        }
        self.entries.remove(path);
        self.symlink_indices.remove(path);
        Ok(true)
    }

    fn has_descendant(&self, path: &Path) -> bool {
        self.entries
            .keys()
            .any(|candidate| candidate != path && candidate.starts_with(path))
    }

    async fn install_symlinks(
        &self,
        target_policy: SymlinkTargetPolicy,
    ) -> Result<(), DecodeError> {
        let mut links = Vec::with_capacity(self.symlinks.len());
        for (index, link) in self.symlinks.iter().enumerate() {
            if self.symlink_indices.get(&link.path) != Some(&index) {
                continue;
            }
            let target = self
                .resolve_terminal(&link.resolved_target)
                .map_err(|reason| link.error(reason))?;
            let kind = match (target, target_policy) {
                (ResolvedTarget::Known(kind), _) => kind,
                (ResolvedTarget::Unowned(_), SymlinkTargetPolicy::ArchiveOnly) => {
                    return Err(link.error("target was not created by this extraction"));
                }
                (ResolvedTarget::Unowned(path), SymlinkTargetPolicy::AllowAmbientAndMissing) => {
                    self.inspect_ambient_target(&path).await?
                }
            };
            let kind = match (kind, link.requires_directory) {
                (TerminalKind::File, true) => {
                    return Err(link.error("target path suffix requires a directory"));
                }
                (TerminalKind::Dangling, true) => TerminalKind::Directory,
                (kind, _) => kind,
            };
            links.push((link, kind));
        }
        for (link, kind) in links {
            let contents = link.link_contents.clone();
            self.with_entry_parent(
                "create symbolic link",
                &link.path,
                move |directory, path| create_symlink(directory, &contents, path, kind),
            )
            .await?;
        }
        Ok(())
    }

    fn resolve_terminal(&self, path: &Path) -> Result<ResolvedTarget, &'static str> {
        let mut path = path.to_owned();
        let mut visited = HashSet::new();
        for _ in 0..=MAX_SYMLINK_EXPANSIONS {
            if !visited.insert(path.clone()) {
                return Err("symbolic-link target cycle");
            }
            let mut components = path.components();
            let mut prefix = PathBuf::new();
            let mut rewritten = None;
            for component in components.by_ref() {
                prefix.push(component.as_os_str());
                if let Some(link_index) = self.symlink_indices.get(&prefix)
                    && let Some(link) = self.symlinks.get(*link_index)
                {
                    let mut target = link.resolved_target.clone();
                    target.extend(components.map(|component| component.as_os_str()));
                    rewritten = Some(target);
                    break;
                }
            }
            if let Some(rewritten) = rewritten {
                path = rewritten;
            } else {
                return Ok(match self.entries.get(&path) {
                    _ if path.as_os_str().is_empty() => {
                        ResolvedTarget::Known(TerminalKind::Directory)
                    }
                    Some(ExtractedEntry::CreatedDirectory) => {
                        ResolvedTarget::Known(TerminalKind::Directory)
                    }
                    Some(ExtractedEntry::File) => ResolvedTarget::Known(TerminalKind::File),
                    Some(ExtractedEntry::Symlink) => continue,
                    Some(ExtractedEntry::AmbientDirectory) | None => ResolvedTarget::Unowned(path),
                });
            }
        }
        Err("symbolic-link target expansion limit exceeded")
    }

    async fn inspect_ambient_target(&self, path: &Path) -> Result<TerminalKind, DecodeError> {
        self.with_root("inspect symbolic-link target", path, |directory, path| {
            if path.as_os_str().is_empty() {
                return Ok(TerminalKind::Directory);
            }
            match directory.metadata(path) {
                Ok(metadata) if metadata.is_dir() => Ok(TerminalKind::Directory),
                Ok(_) => Ok(TerminalKind::File),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(TerminalKind::Dangling),
                Err(error) => Err(error),
            }
        })
        .await
    }

    async fn metadata(&self, path: &Path) -> Result<Option<Metadata>, DecodeError> {
        self.with_entry_parent("inspect", path, |directory, path| {
            match directory.symlink_metadata(path) {
                Ok(metadata) => Ok(Some(metadata)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        })
        .await
    }

    async fn remove_leaf(&mut self, path: &Path, metadata: &Metadata) -> Result<(), DecodeError> {
        if metadata.is_dir() && !metadata_is_link(metadata) {
            let is_empty = self
                .with_entry_parent("inspect directory", path, |root, path| {
                    let directory = root.open_dir(path)?;
                    let mut entries = directory.entries()?;
                    Ok(entries.next().transpose()?.is_none())
                })
                .await?;
            if !is_empty {
                return Err(DecodeError::PathCollision {
                    path: path.to_owned(),
                });
            }
            // Windows directory handles do not share delete access.
            self.directory_handles.remove(path);
            self.with_entry_parent("remove directory", path, |directory, path| {
                directory.remove_dir(path)
            })
            .await
        } else {
            let is_link = metadata_is_link(metadata);
            self.with_entry_parent("remove file", path, move |directory, path| {
                #[cfg(windows)]
                if is_link {
                    // Stable Windows does not expose whether a symlink is file- or
                    // directory-shaped.
                    return match directory.remove_file(path) {
                        Ok(()) => Ok(()),
                        Err(_) => directory.remove_dir(path),
                    };
                }
                #[cfg(not(windows))]
                let _ = is_link;
                directory.remove_file(path)
            })
            .await
        }
    }

    async fn open_file(
        &self,
        operation: &'static str,
        path: &Path,
        create_new: bool,
        truncate: bool,
        executable: bool,
    ) -> Result<File, DecodeError> {
        let file = self
            .with_entry_parent(operation, path, move |directory, path| {
                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .create_new(create_new)
                    .truncate(truncate);
                #[cfg(unix)]
                options.mode(if executable { 0o777 } else { 0o666 });
                #[cfg(not(unix))]
                let _ = executable;
                directory
                    .open_with(path, &options)
                    .map(|file| file.into_std())
            })
            .await?;
        Ok(File::from_std(file))
    }

    async fn create_directory(&self, path: &Path) -> Result<Dir, DecodeError> {
        self.with_entry_parent("create directory", path, |directory, path| {
            directory.create_dir(path)?;
            directory.open_dir(path)
        })
        .await
    }

    async fn open_directory(&self, path: &Path) -> Result<Dir, DecodeError> {
        self.with_entry_parent("open directory", path, |directory, path| {
            directory.open_dir(path)
        })
        .await
    }

    /// Runs an operation against the extraction root capability.
    ///
    /// `path` remains root-relative when passed to `action`. This is used for
    /// paths whose parent is not necessarily an archive-known directory, such
    /// as ambient symbolic-link targets.
    async fn with_root<T, F>(
        &self,
        operation: &'static str,
        path: &Path,
        action: F,
    ) -> Result<T, DecodeError>
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

    /// Runs an operation against the nearest capability for an entry's parent.
    ///
    /// When the immediate parent has a cached [`Dir`], `action` receives that
    /// capability and only the entry's leaf name. Otherwise it receives the
    /// extraction root and the complete root-relative path. Errors always
    /// report the complete path regardless of which capability is selected.
    async fn with_entry_parent<T, F>(
        &self,
        operation: &'static str,
        path: &Path,
        action: F,
    ) -> Result<T, DecodeError>
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
            if let Some(directory) = self.directory_handles.get(parent) {
                return (Arc::clone(directory), file_name.into());
            }
        }
        (Arc::clone(&self.directory), path.to_owned())
    }
}

/// Runs one capability-relative filesystem operation on Tokio's blocking pool.
///
/// `relative_path` is interpreted beneath `directory` and may be only the leaf
/// name when a cached parent capability is available. `error_path` is the full
/// root-relative archive path used for diagnostics; it is never passed to the
/// filesystem. Keeping the paths separate avoids repeated path traversal
/// without losing useful [`DecodeError::Filesystem`] context.
///
/// Filesystem errors are annotated with `operation` and `error_path`, while a
/// failure to join the blocking task becomes [`DecodeError::BlockingTask`].
async fn run_blocking<T, F>(
    directory: Arc<Dir>,
    operation: &'static str,
    error_path: PathBuf,
    relative_path: PathBuf,
    action: F,
) -> Result<T, DecodeError>
where
    T: Send + 'static,
    F: FnOnce(&Dir, &Path) -> io::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || match action(&directory, &relative_path) {
        Ok(result) => Ok(result),
        Err(source) => Err(DecodeError::filesystem(operation, error_path, source)),
    })
    .await
    .map_err(DecodeError::BlockingTask)?
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
fn create_symlink(
    directory: &Dir,
    contents: &Path,
    path: &Path,
    _kind: TerminalKind,
) -> io::Result<()> {
    directory.symlink(contents, path)
}

#[cfg(windows)]
fn create_symlink(
    directory: &Dir,
    contents: &Path,
    path: &Path,
    kind: TerminalKind,
) -> io::Result<()> {
    match kind {
        TerminalKind::File => directory.symlink_file(contents, path),
        TerminalKind::Directory => directory.symlink_dir(contents, path),
        TerminalKind::Dangling => directory.symlink_file(contents, path),
    }
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(
    _directory: &Dir,
    _contents: &Path,
    _path: &Path,
    _kind: TerminalKind,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symbolic links are not supported on this platform",
    ))
}
