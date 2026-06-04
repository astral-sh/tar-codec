//! Filesystem extraction implementation and its private support types.

use std::{
    collections::{HashMap, HashSet},
    fs::{self as std_fs, Metadata},
};

use super::*;
use tar_framing::logical::MemberPayload;
use tokio::{fs, io::AsyncWriteExt};

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
    Directory,
    ExistingDirectory,
    Symlink,
}

impl ExtractedEntry {
    fn is_directory(self) -> bool {
        matches!(self, Self::Directory | Self::ExistingDirectory)
    }
}

struct ExtractionRoot {
    path: PathBuf,
    allow_overwrites: bool,
    entries: HashMap<PathBuf, ExtractedEntry>,
    symlink_indices: HashMap<PathBuf, usize>,
    symlinks: Vec<PendingSymlink>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TerminalKind {
    File,
    Directory,
    Dangling,
}

impl<R: AsyncRead + Unpin> Archive<R> {
    /// Securely extracts this archive beneath `dest` under `policy`.
    ///
    /// The destination is created when missing. When overwrites are enabled,
    /// later members replace earlier members and existing destination leaves
    /// without following symbolic links or recursively removing non-empty
    /// directories. On failure, already-created and replaced entries may
    /// remain, as with conventional streaming tar extractors. The caller must
    /// not concurrently mutate `dest` while extraction is in progress.
    pub async fn extract<P: AsRef<Path>>(
        mut self,
        dest: P,
        policy: DecodePolicy,
    ) -> Result<(), DecodeError> {
        let mut root = ExtractionRoot::open(dest.as_ref(), policy.allow_overwrites).await?;
        let mut payload_chunk = Vec::new();
        while let Some(frame) = self.reader.next_frame().await? {
            policy.check_member(&frame)?;
            let member = decode_member(&frame, &policy)?;
            match member.kind {
                MemberKind::Regular | MemberKind::Contiguous => {
                    root.extract_file(&member, frame.payload, &mut payload_chunk)
                        .await?;
                }
                MemberKind::Directory => {
                    root.extract_directory(&member.path).await?;
                    frame.payload.skip().await?;
                }
                MemberKind::SymbolicLink => {
                    root.reserve_symlink(&member).await?;
                    frame.payload.skip().await?;
                }
                MemberKind::HardLink => {
                    root.extract_hard_link(&member, frame.payload, &mut payload_chunk)
                        .await?;
                }
                MemberKind::CharacterDevice | MemberKind::BlockDevice | MemberKind::Fifo => {
                    return Err(DecodeError::UnsupportedMember {
                        position: member.position,
                        path: member.path,
                        kind: member.kind,
                    });
                }
            }
        }
        root.install_symlinks(policy.allow_dangling_symlinks).await
    }
}

async fn write_payload<R: AsyncRead + Unpin>(
    mut payload: MemberPayload<'_, R>,
    payload_chunk: &mut Vec<u8>,
    path: &Path,
    mut file: fs::File,
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
        let path = tokio::task::spawn_blocking(move || open_destination(&dest))
            .await
            .map_err(DecodeError::BlockingTask)?
            .map_err(|source| {
                DecodeError::filesystem("open destination directory", error_path, source)
            })?;
        Ok(Self {
            path,
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
        if member.payload_size <= EXTRACTION_CHUNK_BYTES as u64 {
            payload_chunk.clear();
            if member.payload_size != 0 {
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
            self.ensure_directory(path, true).await?;
        }
        Ok(())
    }

    async fn create_file(
        &mut self,
        path: &Path,
        executable: bool,
    ) -> Result<fs::File, DecodeError> {
        self.ensure_parents(path).await?;
        if self.symlink_indices.contains_key(path) {
            self.replace_leaf(path).await?;
        }
        let file = match self.open_file(path, true, false, executable).await {
            Ok(file) => file,
            Err(source) => {
                if !self.replace_leaf(path).await? {
                    return Err(DecodeError::filesystem(
                        "create file",
                        path.to_owned(),
                        source,
                    ));
                }
                let result = self.open_file(path, true, false, executable).await;
                self.fs("create file", path, result)?
            }
        };
        self.entries.insert(path.to_owned(), ExtractedEntry::File);
        Ok(file)
    }

    async fn reserve_symlink(&mut self, member: &DecodedMember) -> Result<(), DecodeError> {
        let target_text = member.link_target.clone();
        let target = normalize_symlink_target(member.position, &member.path, &target_text)?;
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
        let result = fs::hard_link(
            self.destination_path(&target),
            self.destination_path(&member.path),
        )
        .await;
        self.fs("create hard link", &member.path, result)?;
        self.entries
            .insert(member.path.clone(), ExtractedEntry::File);
        if member.payload_size == 0 {
            payload.skip().await?;
            Ok(())
        } else {
            let result = self.open_file(&member.path, false, true, false).await;
            let file = self.fs("truncate file", &member.path, result)?;
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
            self.ensure_directory(&current, false).await?;
        }
        Ok(())
    }

    async fn ensure_directory(
        &mut self,
        path: &Path,
        archive_member: bool,
    ) -> Result<(), DecodeError> {
        if let Some(entry) = self.entries.get(path).copied()
            && entry.is_directory()
        {
            if archive_member && entry == ExtractedEntry::ExistingDirectory {
                self.entries
                    .insert(path.to_owned(), ExtractedEntry::Directory);
            }
            return Ok(());
        }
        if self.entries.contains_key(path) {
            self.replace_leaf(path).await?;
        }
        // Missing parents are common, so inspect and replace only after a collision.
        let create_result = fs::create_dir(self.destination_path(path)).await;
        if create_result.is_ok() {
            self.entries
                .insert(path.to_owned(), ExtractedEntry::Directory);
            return Ok(());
        }
        let metadata = self.metadata(path).await?;
        if metadata
            .as_ref()
            .is_some_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        {
            let entry = if archive_member {
                ExtractedEntry::Directory
            } else {
                ExtractedEntry::ExistingDirectory
            };
            self.entries.insert(path.to_owned(), entry);
            return Ok(());
        }
        if metadata.is_none() && !self.entries.contains_key(path) {
            return self.fs("create directory", path, create_result);
        }
        self.replace_leaf(path).await?;
        let result = fs::create_dir(self.destination_path(path)).await;
        self.fs("create directory", path, result)?;
        self.entries
            .insert(path.to_owned(), ExtractedEntry::Directory);
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

    async fn install_symlinks(&self, allow_dangling_symlinks: bool) -> Result<(), DecodeError> {
        let mut links = Vec::with_capacity(self.symlinks.len());
        for (index, link) in self.symlinks.iter().enumerate() {
            if self.symlink_indices.get(&link.path) != Some(&index) {
                continue;
            }
            let kind = self
                .resolve_terminal(&link.resolved_target)
                .map_err(|reason| link.error(reason))?;
            if kind == TerminalKind::Dangling && !allow_dangling_symlinks {
                return Err(link.error("target was not created by this extraction"));
            }
            links.push((link, kind));
        }
        for (link, kind) in links {
            let result = create_symlink(
                &link.link_contents,
                &self.destination_path(&link.path),
                kind,
            )
            .await;
            self.fs("create symbolic link", &link.path, result)?;
        }
        Ok(())
    }

    fn resolve_terminal(&self, path: &Path) -> Result<TerminalKind, &'static str> {
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
                    _ if path.as_os_str().is_empty() => TerminalKind::Directory,
                    Some(ExtractedEntry::Directory) => TerminalKind::Directory,
                    Some(ExtractedEntry::File) => TerminalKind::File,
                    Some(ExtractedEntry::Symlink) => continue,
                    Some(ExtractedEntry::ExistingDirectory) | None => TerminalKind::Dangling,
                });
            }
        }
        Err("symbolic-link target expansion limit exceeded")
    }

    async fn metadata(&self, path: &Path) -> Result<Option<Metadata>, DecodeError> {
        match fs::symlink_metadata(self.destination_path(path)).await {
            Ok(metadata) => Ok(Some(metadata)),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(DecodeError::filesystem("inspect", path.to_owned(), source)),
        }
    }

    async fn remove_leaf(&self, path: &Path, metadata: &Metadata) -> Result<(), DecodeError> {
        let destination = self.destination_path(path);
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let result = fs::read_dir(&destination).await;
            let mut entries = self.fs("inspect directory", path, result)?;
            let result = entries.next_entry().await;
            if self.fs("inspect directory", path, result)?.is_some() {
                return Err(DecodeError::PathCollision {
                    path: path.to_owned(),
                });
            }
            let result = fs::remove_dir(destination).await;
            self.fs("remove directory", path, result)
        } else {
            let result = remove_non_directory(&destination, metadata).await;
            self.fs("remove file", path, result)
        }
    }

    async fn open_file(
        &self,
        path: &Path,
        create_new: bool,
        truncate: bool,
        executable: bool,
    ) -> io::Result<fs::File> {
        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .create_new(create_new)
            .truncate(truncate);
        #[cfg(unix)]
        options.mode(if executable { 0o777 } else { 0o666 });
        #[cfg(not(unix))]
        let _ = executable;
        options.open(self.destination_path(path)).await
    }

    fn destination_path(&self, path: &Path) -> PathBuf {
        self.path.join(path)
    }

    fn fs<T>(
        &self,
        operation: &'static str,
        path: &Path,
        result: io::Result<T>,
    ) -> Result<T, DecodeError> {
        result.map_err(|source| DecodeError::filesystem(operation, path.to_owned(), source))
    }
}

fn open_destination(dest: &Path) -> io::Result<PathBuf> {
    match std_fs::symlink_metadata(dest) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => std_fs::create_dir_all(dest)?,
        Err(error) => return Err(error),
    }
    let metadata = std_fs::symlink_metadata(dest)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other("destination is not a real directory"));
    }
    std_fs::canonicalize(dest)
}

async fn remove_non_directory(path: &Path, metadata: &Metadata) -> io::Result<()> {
    #[cfg(windows)]
    if metadata.file_type().is_symlink() {
        // Stable Windows does not expose whether a symlink is file- or directory-shaped.
        return match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(_) => fs::remove_dir(path).await,
        };
    }
    #[cfg(not(windows))]
    let _ = metadata;
    fs::remove_file(path).await
}

#[cfg(unix)]
async fn create_symlink(contents: &Path, path: &Path, _kind: TerminalKind) -> io::Result<()> {
    fs::symlink(contents, path).await
}

#[cfg(windows)]
async fn create_symlink(contents: &Path, path: &Path, kind: TerminalKind) -> io::Result<()> {
    match kind {
        TerminalKind::File => fs::symlink_file(contents, path).await,
        TerminalKind::Directory => fs::symlink_dir(contents, path).await,
        TerminalKind::Dangling => fs::symlink_file(contents, path).await,
    }
}

#[cfg(not(any(unix, windows)))]
async fn create_symlink(_contents: &Path, _path: &Path, _kind: TerminalKind) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symbolic links are not supported on this platform",
    ))
}
