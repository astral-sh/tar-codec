//! Filesystem extraction implementation and its private support types.

use std::{
    collections::{HashMap, HashSet},
    fs::{self as std_fs, Metadata},
};

use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tar_framing::logical::MemberPayload;
use tokio::{fs, io::AsyncWriteExt};

#[derive(Clone, Debug)]
struct PendingSymlink {
    path: PathBuf,
    position: u64,
    target_text: String,
    target: PathBuf,
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
            let member = decode_member(&frame)?;
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
        let file = match self.open_file(path, true, false).await {
            Ok(file) => file,
            Err(source) => {
                if !self.replace_leaf(path).await? {
                    return Err(DecodeError::filesystem(
                        "create file",
                        path.to_owned(),
                        source,
                    ));
                }
                let result = self.open_file(path, true, false).await;
                self.fs("create file", path, result)?
            }
        };
        let result = add_executable(&file, executable).await;
        self.fs("create file", path, result)?;
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
            target,
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
        let target = normalize_path(member.position, "hard-link target", &target_text, &[])?;
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
            let result = self.open_file(&member.path, false, true).await;
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
            return Err(DecodeError::path_collision(path.to_owned()));
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
                .resolve_terminal(&link.target)
                .map_err(|reason| link.error(reason))?;
            if kind == TerminalKind::Dangling && !allow_dangling_symlinks {
                return Err(link.error("target was not created by this extraction"));
            }
            links.push((link, kind));
        }
        for (link, kind) in links {
            let contents = relative_link_contents(&link.path, &link.target);
            let result = create_symlink(&contents, &self.destination_path(&link.path), kind).await;
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
                    let mut target = link.target.clone();
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
                return Err(DecodeError::path_collision(path.to_owned()));
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
    ) -> io::Result<fs::File> {
        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .create_new(create_new)
            .truncate(truncate);
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
async fn add_executable(file: &fs::File, executable: bool) -> io::Result<()> {
    if executable {
        let mut permissions = file.metadata().await?.permissions();
        permissions.set_mode(permissions.mode() | 0o111);
        file.set_permissions(permissions).await?;
    }
    Ok(())
}

#[cfg(not(unix))]
async fn add_executable(_file: &fs::File, _executable: bool) -> io::Result<()> {
    Ok(())
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

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_file;
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink as symlink_dir};
    #[cfg(windows)]
    use std::os::windows::fs::{symlink_dir, symlink_file};

    use super::*;
    use crate::test_support::ChunkedReader;
    use tar_framing::{BLOCK_SIZE, Block, FrameErrorInner};
    use tempfile::tempdir;

    const NAME_RANGE: std::ops::Range<usize> = 0..100;
    const MODE_RANGE: std::ops::Range<usize> = 100..108;
    const LINK_NAME_RANGE: std::ops::Range<usize> = 157..257;
    const SIZE_RANGE: std::ops::Range<usize> = 124..136;
    const CHECKSUM_RANGE: std::ops::Range<usize> = 148..156;
    const TYPEFLAG_OFFSET: usize = 156;
    const IDENTITY_RANGE: std::ops::Range<usize> = 257..265;
    const POSIX_IDENTITY: &[u8; 8] = b"ustar\x0000";
    const GNU_IDENTITY: &[u8; 8] = b"ustar  \0";

    fn header(
        identity: &[u8; 8],
        name: &str,
        typeflag: u8,
        size: u64,
        link_name: &str,
        mode: u32,
    ) -> Block {
        let mut block = [0; BLOCK_SIZE];
        set_text(&mut block[NAME_RANGE], name);
        block[MODE_RANGE].copy_from_slice(format!("{mode:07o}\0").as_bytes());
        block[SIZE_RANGE].copy_from_slice(format!("{size:011o}\0").as_bytes());
        block[TYPEFLAG_OFFSET] = typeflag;
        set_text(&mut block[LINK_NAME_RANGE], link_name);
        block[IDENTITY_RANGE].copy_from_slice(identity);
        set_checksum(&mut block);
        block
    }

    fn set_text(field: &mut [u8], value: &str) {
        assert!(value.len() < field.len());
        field[..value.len()].copy_from_slice(value.as_bytes());
    }

    fn set_checksum(block: &mut Block) {
        block[CHECKSUM_RANGE].fill(b' ');
        let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
        block[CHECKSUM_RANGE].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    }

    fn record(keyword: &str, value: &str) -> Vec<u8> {
        raw_record(keyword, value.as_bytes())
    }

    fn raw_record(keyword: &str, value: &[u8]) -> Vec<u8> {
        let mut suffix = format!(" {keyword}=").into_bytes();
        suffix.extend_from_slice(value);
        suffix.push(b'\n');
        let mut len = suffix.len() + 1;
        loop {
            let prefix = len.to_string();
            let actual = prefix.len() + suffix.len();
            if actual == len {
                let mut record = prefix.into_bytes();
                record.extend_from_slice(&suffix);
                return record;
            }
            len = actual;
        }
    }

    fn append_block(bytes: &mut Vec<u8>, block: &Block) {
        bytes.extend_from_slice(block);
    }

    fn append_payload(bytes: &mut Vec<u8>, payload: &[u8]) {
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().next_multiple_of(BLOCK_SIZE), 0);
    }

    fn append_posix_member(
        bytes: &mut Vec<u8>,
        name: &str,
        typeflag: u8,
        payload: &[u8],
        link_name: &str,
        mode: u32,
    ) {
        append_block(
            bytes,
            &header(
                POSIX_IDENTITY,
                name,
                typeflag,
                payload.len() as u64,
                link_name,
                mode,
            ),
        );
        append_payload(bytes, payload);
    }

    #[derive(Clone, Copy)]
    enum TestEntryKind {
        File,
        Directory,
        SymbolicLink,
        HardLink,
    }

    fn append_test_entry(bytes: &mut Vec<u8>, name: &str, kind: TestEntryKind, payload: &[u8]) {
        let (typeflag, payload, link_name) = match kind {
            TestEntryKind::File => (b'0', payload, ""),
            TestEntryKind::Directory => (b'5', &[][..], ""),
            TestEntryKind::SymbolicLink => (b'2', &[][..], "target"),
            TestEntryKind::HardLink => (b'1', &[][..], "target"),
        };
        append_posix_member(bytes, name, typeflag, payload, link_name, 0o644);
    }

    fn append_gnu_member(
        bytes: &mut Vec<u8>,
        name: &str,
        typeflag: u8,
        payload: &[u8],
        link_name: &str,
        mode: u32,
    ) {
        append_block(
            bytes,
            &header(
                GNU_IDENTITY,
                name,
                typeflag,
                payload.len() as u64,
                link_name,
                mode,
            ),
        );
        append_payload(bytes, payload);
    }

    fn append_pax(bytes: &mut Vec<u8>, typeflag: u8, payload: &[u8]) {
        append_posix_member(bytes, "pax", typeflag, payload, "", 0o644);
    }

    fn finish(bytes: &mut Vec<u8>) {
        bytes.resize(bytes.len() + 2 * BLOCK_SIZE, 0);
    }

    fn single_posix_member_archive(
        name: &str,
        typeflag: u8,
        payload: &[u8],
        link_name: &str,
        mode: u32,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, name, typeflag, payload, link_name, mode);
        finish(&mut bytes);
        bytes
    }

    type DecodeErrorMatcher = fn(&DecodeError) -> bool;

    async fn extract(bytes: Vec<u8>, dest: &Path) -> Result<(), DecodeError> {
        extract_with_policy(bytes, dest, DecodePolicy::default()).await
    }

    async fn extract_with_policy(
        bytes: Vec<u8>,
        dest: &Path,
        policy: DecodePolicy,
    ) -> Result<(), DecodeError> {
        Archive::new(ChunkedReader::new(bytes, 23))
            .extract(dest, policy)
            .await
    }

    #[tokio::test]
    async fn extracts_posix_files_directories_and_executable_intent() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "bin/tool", b'0', b"run", "", 0o755);
        append_posix_member(&mut bytes, "bin", b'5', b"", "", 0o755);
        append_posix_member(&mut bytes, "empty", b'5', b"", "", 0o755);
        append_posix_member(&mut bytes, ".", b'5', b"", "", 0o755);
        finish(&mut bytes);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("bin/tool")).unwrap(), b"run");
        assert!(dest.join("empty").is_dir());
        #[cfg(unix)]
        {
            assert_ne!(
                std::fs::metadata(dest.join("bin/tool"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
    }

    #[tokio::test]
    async fn rejects_non_directory_extraction_roots_without_modifying_them() {
        let temp = tempdir().unwrap();
        let bytes = single_posix_member_archive("file", b'0', b"archive", "", 0o644);

        let file_dest = temp.path().join("file");
        std::fs::write(&file_dest, b"keep").unwrap();
        let error = extract(bytes.clone(), &file_dest).await.unwrap_err();
        assert!(matches!(error, DecodeError::Filesystem { .. }));
        assert_eq!(std::fs::read(&file_dest).unwrap(), b"keep");

        #[cfg(any(unix, windows))]
        {
            let target = temp.path().join("target");
            let link_dest = temp.path().join("link");
            std::fs::create_dir(&target).unwrap();
            std::fs::write(target.join("keep"), b"keep").unwrap();
            symlink_dir(&target, &link_dest).unwrap();

            let error = extract(bytes, &link_dest).await.unwrap_err();
            assert!(matches!(error, DecodeError::Filesystem { .. }));
            assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"keep");
            assert!(!target.join("file").exists());
        }
    }

    #[tokio::test]
    async fn extracts_buffered_and_streamed_multiblock_payloads_over_empty_directories() {
        for (case, payload_len) in [
            ("buffered", 16 * 1024 + BLOCK_SIZE + 7),
            ("streamed", EXTRACTION_CHUNK_BYTES + 7),
        ] {
            let temp = tempdir().unwrap();
            let dest = temp.path().join("out");
            let payload = (0..payload_len)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect::<Vec<_>>();
            let bytes = single_posix_member_archive("file", b'0', &payload, "", 0o644);
            std::fs::create_dir_all(dest.join("file")).unwrap();

            extract(bytes, &dest).await.unwrap();
            assert_eq!(std::fs::read(dest.join("file")).unwrap(), payload, "{case}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn extracts_paths_with_non_prefix_colons() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_posix_member(
            &mut bytes,
            "tests/snippets/ballon:main.py",
            b'0',
            b"ok",
            "",
            0o644,
        );
        finish(&mut bytes);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("tests/snippets/ballon:main.py")).unwrap(),
            "ok"
        );
    }

    #[tokio::test]
    async fn applies_posix_path_and_linkpath_precedence_when_globals_are_allowed() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let global = record("path", "wrong");
        let local_file = record("path", "actual/file");
        let mut local_link = record("path", "actual/link");
        local_link.extend_from_slice(&record("linkpath", "file"));
        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'g', &global);
        append_pax(&mut bytes, b'x', &local_file);
        append_posix_member(&mut bytes, "raw", b'0', b"content", "", 0o644);
        append_pax(&mut bytes, b'x', &local_link);
        append_posix_member(&mut bytes, "raw-link", b'2', b"", "wrong-target", 0o644);
        finish(&mut bytes);

        extract_with_policy(
            bytes,
            &dest,
            DecodePolicy::default().pax_policy(
                PaxDecodePolicy::default()
                    .allow_global_pax_extensions(true)
                    .allow_global_pax_member_metadata(true),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("actual/link")).unwrap(),
            "content"
        );
        assert!(!dest.join("wrong").exists());
    }

    #[tokio::test]
    async fn applies_single_and_multiblock_gnu_long_name_and_long_link_metadata() {
        let prefix = "./".repeat(BLOCK_SIZE);
        let mut long_name = format!("{prefix}alias").into_bytes();
        long_name.push(0);
        let mut long_link = format!("{prefix}target").into_bytes();
        long_link.push(0);

        for (case, target, long_name, long_link, expected_path) in [
            (
                "single-block",
                "dir/target",
                b"dir/long/link\0".to_vec(),
                b"../target\0".to_vec(),
                "dir/long/link",
            ),
            ("multiblock", "target", long_name, long_link, "alias"),
        ] {
            let temp = tempdir().unwrap();
            let dest = temp.path().join("out");
            let mut bytes = Vec::new();
            append_gnu_member(&mut bytes, target, b'0', b"contents", "", 0o644);
            append_gnu_member(&mut bytes, "longname", b'L', &long_name, "", 0o644);
            append_gnu_member(&mut bytes, "longlink", b'K', &long_link, "", 0o644);
            append_gnu_member(&mut bytes, "raw", b'2', b"", "wrong", 0o644);
            finish(&mut bytes);

            extract(bytes, &dest).await.unwrap();
            assert_eq!(
                std::fs::read_to_string(dest.join(expected_path)).unwrap(),
                "contents",
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_unsafe_paths_cross_kind_collisions_and_unsupported_members() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir(dest.join("occupied")).unwrap();
        std::fs::write(dest.join("occupied/child"), b"keep").unwrap();

        for (case, name, kind, expected) in [
            (
                "unsafe path",
                "../escape",
                b'0',
                (|error| matches!(error, DecodeError::UnsafePath { .. })) as DecodeErrorMatcher,
            ),
            ("path collision", "occupied", b'0', |error| {
                matches!(error, DecodeError::PathCollision { .. })
            }),
            ("unsupported member", "device", b'3', |error| {
                matches!(error, DecodeError::UnsupportedMember { .. })
            }),
        ] {
            let bytes = single_posix_member_archive(name, kind, b"", "", 0o644);
            let error = extract(bytes, &dest).await.unwrap_err();
            assert!(expected(&error), "{case}: {error:?}");
        }
        assert!(dest.join("occupied").is_dir());
        assert_eq!(std::fs::read(dest.join("occupied/child")).unwrap(), b"keep");
        assert!(!temp.path().join("escape").exists());
    }

    #[tokio::test]
    async fn overwrites_duplicate_and_normalized_regular_file_paths_by_default() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "same", b'0', b"old", "", 0o644);
        append_posix_member(&mut bytes, "same", b'0', b"new", "", 0o644);
        append_posix_member(&mut bytes, "nested/../normalized", b'0', b"old", "", 0o644);
        append_posix_member(&mut bytes, "normalized", b'0', b"new", "", 0o644);
        finish(&mut bytes);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("same")).unwrap(), b"new");
        assert_eq!(std::fs::read(dest.join("normalized")).unwrap(), b"new");
    }

    #[tokio::test]
    async fn overwrites_ambient_regular_files_by_default() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("same"), b"ambient").unwrap();
        let bytes = single_posix_member_archive("same", b'0', b"archive", "", 0o644);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("same")).unwrap(), b"archive");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ambient_regular_file_replacement_unlinks_inode_and_applies_mode() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(dest.join("same"), b"ambient").unwrap();
        std::fs::hard_link(dest.join("same"), dest.join("sibling")).unwrap();
        let bytes = single_posix_member_archive("same", b'0', b"archive", "", 0o755);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("same")).unwrap(), b"archive");
        assert_eq!(std::fs::read(dest.join("sibling")).unwrap(), b"ambient");
        let replaced = std::fs::metadata(dest.join("same")).unwrap();
        let sibling = std::fs::metadata(dest.join("sibling")).unwrap();
        assert_ne!(replaced.ino(), sibling.ino());
        assert_ne!(replaced.permissions().mode() & 0o111, 0);
    }

    #[tokio::test]
    async fn later_entries_overwrite_cross_kind_normalized_paths_by_default() {
        let temp = tempdir().unwrap();
        for (case, first, last) in [
            (
                "file-to-directory",
                TestEntryKind::File,
                TestEntryKind::Directory,
            ),
            (
                "file-to-symbolic-link",
                TestEntryKind::File,
                TestEntryKind::SymbolicLink,
            ),
            (
                "file-to-hard-link",
                TestEntryKind::File,
                TestEntryKind::HardLink,
            ),
            (
                "directory-to-file",
                TestEntryKind::Directory,
                TestEntryKind::File,
            ),
            (
                "directory-to-symbolic-link",
                TestEntryKind::Directory,
                TestEntryKind::SymbolicLink,
            ),
            (
                "directory-to-hard-link",
                TestEntryKind::Directory,
                TestEntryKind::HardLink,
            ),
            (
                "symbolic-link-to-file",
                TestEntryKind::SymbolicLink,
                TestEntryKind::File,
            ),
            (
                "symbolic-link-to-directory",
                TestEntryKind::SymbolicLink,
                TestEntryKind::Directory,
            ),
            (
                "symbolic-link-to-hard-link",
                TestEntryKind::SymbolicLink,
                TestEntryKind::HardLink,
            ),
            (
                "hard-link-to-file",
                TestEntryKind::HardLink,
                TestEntryKind::File,
            ),
            (
                "hard-link-to-directory",
                TestEntryKind::HardLink,
                TestEntryKind::Directory,
            ),
            (
                "hard-link-to-symbolic-link",
                TestEntryKind::HardLink,
                TestEntryKind::SymbolicLink,
            ),
        ] {
            let dest = temp.path().join(case);
            let mut bytes = Vec::new();
            append_posix_member(&mut bytes, "target", b'0', b"target", "", 0o644);
            append_test_entry(&mut bytes, "nested/../same", first, b"first");
            append_test_entry(&mut bytes, "same", last, b"last");
            finish(&mut bytes);

            extract_with_policy(bytes, &dest, DecodePolicy::default().allow_hard_links(true))
                .await
                .unwrap();
            match last {
                TestEntryKind::File => {
                    assert_eq!(std::fs::read(dest.join("same")).unwrap(), b"last", "{case}");
                }
                TestEntryKind::Directory => {
                    assert!(dest.join("same").is_dir(), "{case}");
                }
                TestEntryKind::SymbolicLink => {
                    assert_eq!(
                        std::fs::read_link(dest.join("same")).unwrap(),
                        Path::new("target"),
                        "{case}"
                    );
                }
                TestEntryKind::HardLink => {
                    std::fs::write(dest.join("target"), b"updated").unwrap();
                    assert_eq!(
                        std::fs::read(dest.join("same")).unwrap(),
                        b"updated",
                        "{case}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn later_link_entries_overwrite_same_kind_paths_by_default() {
        let temp = tempdir().unwrap();
        for (case, typeflag) in [("symbolic-link", b'2'), ("hard-link", b'1')] {
            let dest = temp.path().join(case);
            let mut bytes = Vec::new();
            append_posix_member(&mut bytes, "first", b'0', b"first", "", 0o644);
            append_posix_member(&mut bytes, "second", b'0', b"second", "", 0o644);
            append_posix_member(&mut bytes, "same", typeflag, b"", "first", 0o644);
            append_posix_member(&mut bytes, "same", typeflag, b"", "second", 0o644);
            finish(&mut bytes);

            extract_with_policy(bytes, &dest, DecodePolicy::default().allow_hard_links(true))
                .await
                .unwrap();
            assert_eq!(
                std::fs::read(dest.join("same")).unwrap(),
                b"second",
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn overwrites_preexisting_file_and_empty_directory_leaves_by_default() {
        let temp = tempdir().unwrap();
        for (case, existing_file, archive) in [
            ("file-to-directory", true, TestEntryKind::Directory),
            ("file-to-symbolic-link", true, TestEntryKind::SymbolicLink),
            ("directory-to-file", false, TestEntryKind::File),
            ("directory-to-hard-link", false, TestEntryKind::HardLink),
        ] {
            let dest = temp.path().join(case);
            std::fs::create_dir(&dest).unwrap();
            if existing_file {
                std::fs::write(dest.join("same"), b"ambient").unwrap();
            } else {
                std::fs::create_dir(dest.join("same")).unwrap();
            }
            let mut bytes = Vec::new();
            append_posix_member(&mut bytes, "target", b'0', b"target", "", 0o644);
            append_test_entry(&mut bytes, "same", archive, b"archive");
            finish(&mut bytes);

            extract_with_policy(bytes, &dest, DecodePolicy::default().allow_hard_links(true))
                .await
                .unwrap();
            match archive {
                TestEntryKind::File => {
                    assert_eq!(std::fs::read(dest.join("same")).unwrap(), b"archive");
                }
                TestEntryKind::Directory => assert!(dest.join("same").is_dir()),
                TestEntryKind::SymbolicLink => {
                    assert_eq!(
                        std::fs::read_link(dest.join("same")).unwrap(),
                        Path::new("target")
                    );
                }
                TestEntryKind::HardLink => {
                    std::fs::write(dest.join("target"), b"updated").unwrap();
                    assert_eq!(std::fs::read(dest.join("same")).unwrap(), b"updated");
                }
            }
        }
    }

    #[tokio::test]
    async fn promotes_earlier_non_directory_parents_by_default() {
        let temp = tempdir().unwrap();
        for (case, parent) in [
            ("file-parent", TestEntryKind::File),
            ("symbolic-link-parent", TestEntryKind::SymbolicLink),
        ] {
            let dest = temp.path().join(case);
            let mut bytes = Vec::new();
            append_test_entry(&mut bytes, "parent", parent, b"old");
            append_posix_member(&mut bytes, "parent/child", b'0', b"new", "", 0o644);
            finish(&mut bytes);

            extract(bytes, &dest).await.unwrap();
            assert_eq!(
                std::fs::read(dest.join("parent/child")).unwrap(),
                b"new",
                "{case}"
            );
        }

        let ambient_dest = temp.path().join("ambient-file-parent");
        std::fs::create_dir(&ambient_dest).unwrap();
        std::fs::write(ambient_dest.join("parent"), b"old").unwrap();
        let bytes = single_posix_member_archive("parent/child", b'0', b"new", "", 0o644);

        extract(bytes, &ambient_dest).await.unwrap();
        assert_eq!(
            std::fs::read(ambient_dest.join("parent/child")).unwrap(),
            b"new"
        );
    }

    #[tokio::test]
    async fn disabled_overwrites_reject_replacements_but_reuse_real_directories() {
        let temp = tempdir().unwrap();
        let mut duplicate = Vec::new();
        append_posix_member(&mut duplicate, "same", b'0', b"old", "", 0o644);
        append_posix_member(&mut duplicate, "same", b'0', b"new", "", 0o644);
        finish(&mut duplicate);
        let mut cross_kind = Vec::new();
        append_posix_member(&mut cross_kind, "same", b'0', b"old", "", 0o644);
        append_posix_member(&mut cross_kind, "same", b'5', b"", "", 0o755);
        finish(&mut cross_kind);
        let mut parent = Vec::new();
        append_posix_member(&mut parent, "parent", b'0', b"old", "", 0o644);
        append_posix_member(&mut parent, "parent/child", b'0', b"new", "", 0o644);
        finish(&mut parent);
        let mut pending_symlink = Vec::new();
        append_posix_member(&mut pending_symlink, "same", b'2', b"", "missing", 0o644);
        append_posix_member(&mut pending_symlink, "same", b'0', b"new", "", 0o644);
        finish(&mut pending_symlink);
        let ambient = single_posix_member_archive("same", b'0', b"new", "", 0o644);

        for (case, bytes, preexisting_file) in [
            ("duplicate", duplicate, false),
            ("cross-kind", cross_kind, false),
            ("non-directory-parent", parent, false),
            ("pending-symlink", pending_symlink, false),
            ("preexisting-file", ambient, true),
        ] {
            let dest = temp.path().join(case);
            if preexisting_file {
                std::fs::create_dir(&dest).unwrap();
                std::fs::write(dest.join("same"), b"ambient").unwrap();
            }
            let error = extract_with_policy(
                bytes,
                &dest,
                DecodePolicy::default().allow_overwrites(false),
            )
            .await
            .unwrap_err();
            assert!(matches!(error, DecodeError::PathCollision { .. }), "{case}");
        }

        let directory_dest = temp.path().join("directories");
        std::fs::create_dir_all(directory_dest.join("same")).unwrap();
        let mut directories = Vec::new();
        append_posix_member(&mut directories, "same/child", b'0', b"new", "", 0o644);
        append_posix_member(&mut directories, "same", b'5', b"", "", 0o755);
        append_posix_member(&mut directories, "same", b'5', b"", "", 0o755);
        finish(&mut directories);

        extract_with_policy(
            directories,
            &directory_dest,
            DecodePolicy::default().allow_overwrites(false),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(directory_dest.join("same/child")).unwrap(),
            b"new"
        );
    }

    #[tokio::test]
    async fn refuses_to_replace_physically_or_logically_non_empty_directories() {
        let temp = tempdir().unwrap();
        let mut archive_child = Vec::new();
        append_posix_member(&mut archive_child, "same/child", b'0', b"keep", "", 0o644);
        append_posix_member(&mut archive_child, "same", b'0', b"replace", "", 0o644);
        finish(&mut archive_child);
        let mut pending_child = Vec::new();
        append_posix_member(&mut pending_child, "same/link", b'2', b"", "missing", 0o644);
        append_posix_member(&mut pending_child, "same", b'0', b"replace", "", 0o644);
        finish(&mut pending_child);
        let ambient_child = single_posix_member_archive("same", b'0', b"replace", "", 0o644);

        for (case, bytes, preexisting_child) in [
            ("archive-child", archive_child, false),
            ("pending-symlink-child", pending_child, false),
            ("preexisting-child", ambient_child, true),
        ] {
            let dest = temp.path().join(case);
            if preexisting_child {
                std::fs::create_dir_all(dest.join("same")).unwrap();
                std::fs::write(dest.join("same/child"), b"keep").unwrap();
            }
            let error = extract(bytes, &dest).await.unwrap_err();
            assert!(matches!(error, DecodeError::PathCollision { .. }), "{case}");
            assert!(dest.join("same").is_dir(), "{case}");
        }
    }

    #[tokio::test]
    async fn canceled_pending_symlinks_do_not_affect_installation_or_resolution() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "obsolete", b'2', b"", "missing", 0o644);
        append_posix_member(&mut bytes, "obsolete", b'0', b"file", "", 0o644);
        append_posix_member(&mut bytes, "alias", b'2', b"", "target", 0o644);
        append_posix_member(&mut bytes, "target", b'2', b"", "missing", 0o644);
        append_posix_member(&mut bytes, "target", b'0', b"target", "", 0o644);
        finish(&mut bytes);

        extract_with_policy(
            bytes,
            &dest,
            DecodePolicy::default().allow_dangling_symlinks(false),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(dest.join("obsolete")).unwrap(), b"file");
        assert_eq!(std::fs::read(dest.join("alias")).unwrap(), b"target");
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn replaces_preexisting_symlink_parents_without_following_them() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink_dir(&outside, dest.join("parent")).unwrap();
        let bytes = single_posix_member_archive("parent/file", b'0', b"good", "", 0o644);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("parent/file")).unwrap(), b"good");
        assert!(!outside.join("file").exists());
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn replaces_preexisting_final_symlinks_instead_of_following_them() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(&outside, b"keep").unwrap();
        symlink_file(&outside, dest.join("same")).unwrap();
        let bytes = single_posix_member_archive("same", b'0', b"bad", "", 0o644);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("same")).unwrap(), b"bad");
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    }

    #[tokio::test]
    async fn creates_safe_and_dangling_symlink_chains() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("good");
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "dir/file", b'0', b"ok", "", 0o644);
        append_posix_member(&mut bytes, "dir/one", b'2', b"", "file", 0o644);
        append_posix_member(&mut bytes, "two", b'2', b"", "dir/one", 0o644);
        finish(&mut bytes);
        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read_to_string(dest.join("two")).unwrap(), "ok");

        let dangling_dest = temp.path().join("dangling");
        let dangling = single_posix_member_archive("link", b'2', b"", "missing", 0o644);
        extract(dangling, &dangling_dest).await.unwrap();
        assert_eq!(
            std::fs::read_link(dangling_dest.join("link")).unwrap(),
            Path::new("missing")
        );

        let chain_dest = temp.path().join("dangling-chain");
        let mut chain = Vec::new();
        append_posix_member(&mut chain, "one", b'2', b"", "two", 0o644);
        append_posix_member(&mut chain, "two", b'2', b"", "missing", 0o644);
        finish(&mut chain);
        extract(chain, &chain_dest).await.unwrap();
        assert_eq!(
            std::fs::read_link(chain_dest.join("one")).unwrap(),
            Path::new("two")
        );
        assert_eq!(
            std::fs::read_link(chain_dest.join("two")).unwrap(),
            Path::new("missing")
        );
    }

    #[tokio::test]
    async fn strict_dangling_symlink_policy_distinguishes_missing_targets_and_root() {
        let temp = tempdir().unwrap();
        for (case, target, allowed) in [("missing", "missing", false), ("root", ".", true)] {
            let dest = temp.path().join(case);
            let bytes = single_posix_member_archive("link", b'2', b"", target, 0o644);
            let result = extract_with_policy(
                bytes,
                &dest,
                DecodePolicy::default().allow_dangling_symlinks(false),
            )
            .await;
            if allowed {
                result.unwrap();
                assert_eq!(
                    std::fs::read_link(dest.join("link")).unwrap(),
                    Path::new(target),
                    "{case}"
                );
            } else {
                assert!(
                    matches!(result, Err(DecodeError::InvalidLink { .. })),
                    "{case}"
                );
                assert!(!dest.join("link").exists(), "{case}");
            }
        }
    }

    #[tokio::test]
    async fn allows_repeated_finite_symbolic_link_expansion() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "file", b'0', b"ok", "", 0o644);
        append_posix_member(&mut bytes, "a", b'2', b"", ".", 0o644);
        append_posix_member(&mut bytes, "b", b'2', b"", "a/a/file", 0o644);
        finish(&mut bytes);
        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read_to_string(dest.join("b")).unwrap(), "ok");
    }

    #[tokio::test]
    async fn rejects_symbolic_link_cycles_and_root_escapes() {
        let temp = tempdir().unwrap();
        for (case, first_target, second_target, expected) in [
            (
                "cycle",
                "b",
                "a",
                (|error| matches!(error, DecodeError::InvalidLink { .. })) as DecodeErrorMatcher,
            ),
            ("growing-cycle", "b/x", "a/y", |error| {
                matches!(
                    error,
                    DecodeError::InvalidLink {
                        reason: "symbolic-link target expansion limit exceeded",
                        ..
                    }
                )
            }),
        ] {
            let dest = temp.path().join(case);
            let mut bytes = Vec::new();
            append_posix_member(&mut bytes, "a", b'2', b"", first_target, 0o644);
            append_posix_member(&mut bytes, "b", b'2', b"", second_target, 0o644);
            finish(&mut bytes);

            let error = extract(bytes, &dest).await.unwrap_err();
            assert!(expected(&error), "{case}: {error:?}");
            assert!(!dest.join("a").exists(), "{case}");
            assert!(!dest.join("b").exists(), "{case}");
        }

        let escape_dest = temp.path().join("escape");
        let escape = single_posix_member_archive("link", b'2', b"", "../outside", 0o644);
        let error = extract(escape, &escape_dest).await.unwrap_err();
        assert!(matches!(error, DecodeError::UnsafePath { .. }));
        assert!(!escape_dest.join("link").exists());
    }

    #[tokio::test]
    async fn extracts_prior_target_hard_links_with_linkdata_and_differing_modes() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let policy = DecodePolicy::default().allow_hard_links(true);
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "a", b'0', b"old", "", 0o644);
        append_posix_member(&mut bytes, "b", b'1', b"new", "a", 0o644);
        finish(&mut bytes);
        extract_with_policy(bytes, &dest, policy).await.unwrap();
        assert_eq!(std::fs::read(dest.join("a")).unwrap(), b"new");
        assert_eq!(std::fs::read(dest.join("b")).unwrap(), b"new");

        let unresolved = single_posix_member_archive("b", b'1', b"", "a", 0o644);
        let forward_dest = temp.path().join("forward");
        assert!(matches!(
            extract_with_policy(unresolved.clone(), &forward_dest, policy)
                .await
                .unwrap_err(),
            DecodeError::InvalidLink { .. }
        ));

        let ambient_dest = temp.path().join("ambient");
        std::fs::create_dir(&ambient_dest).unwrap();
        std::fs::write(ambient_dest.join("a"), b"ambient").unwrap();
        assert!(matches!(
            extract_with_policy(unresolved, &ambient_dest, policy)
                .await
                .unwrap_err(),
            DecodeError::InvalidLink { .. }
        ));
        assert_eq!(std::fs::read(ambient_dest.join("a")).unwrap(), b"ambient");
        assert!(!ambient_dest.join("b").exists());

        let differing_mode_dest = temp.path().join("differing-mode");
        let mut differing_mode = Vec::new();
        append_posix_member(&mut differing_mode, "a", b'0', b"", "", 0o644);
        append_posix_member(&mut differing_mode, "b", b'1', b"", "a", 0o755);
        finish(&mut differing_mode);
        extract_with_policy(differing_mode, &differing_mode_dest, policy)
            .await
            .unwrap();
        assert!(differing_mode_dest.join("b").is_file());

        #[cfg(unix)]
        {
            let linkdata_mode_dest = temp.path().join("linkdata-mode");
            let mut linkdata_mode = Vec::new();
            append_posix_member(&mut linkdata_mode, "a", b'0', b"old", "", 0o644);
            append_posix_member(&mut linkdata_mode, "b", b'1', b"new", "a", 0o755);
            finish(&mut linkdata_mode);
            extract_with_policy(linkdata_mode, &linkdata_mode_dest, policy)
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(linkdata_mode_dest.join("a"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }
    }

    #[tokio::test]
    async fn rejects_hard_links_that_would_replace_their_targets() {
        let temp = tempdir().unwrap();
        for (case, path) in [("self", "target"), ("ancestor", "target/link")] {
            let dest = temp.path().join(case);
            let mut bytes = Vec::new();
            append_posix_member(&mut bytes, "target", b'0', b"keep", "", 0o644);
            append_posix_member(&mut bytes, path, b'1', b"", "target", 0o644);
            finish(&mut bytes);

            let error =
                extract_with_policy(bytes, &dest, DecodePolicy::default().allow_hard_links(true))
                    .await
                    .unwrap_err();
            assert!(matches!(error, DecodeError::InvalidLink { .. }), "{case}");
            assert_eq!(std::fs::read(dest.join("target")).unwrap(), b"keep");
        }
    }

    #[tokio::test]
    async fn enforces_symbolic_and_hard_link_policies_before_link_creation() {
        let temp = tempdir().unwrap();
        let symlink_dest = temp.path().join("symlink");
        let mut symlink = Vec::new();
        append_posix_member(&mut symlink, "target", b'0', b"ok", "", 0o644);
        append_posix_member(&mut symlink, "link", b'2', b"", "target", 0o644);
        finish(&mut symlink);
        assert!(matches!(
            extract_with_policy(
                symlink,
                &symlink_dest,
                DecodePolicy::default().allow_symlinks(false)
            )
            .await
            .unwrap_err(),
            DecodeError::PolicyViolation {
                position: 1024,
                violation: DecodePolicyViolation::SymbolicLink,
            }
        ));
        assert_eq!(
            std::fs::read_to_string(symlink_dest.join("target")).unwrap(),
            "ok"
        );
        assert!(!symlink_dest.join("link").exists());

        let hard_link_dest = temp.path().join("hard-link");
        let hard_link = single_posix_member_archive("link", b'1', b"", "missing", 0o644);
        assert!(matches!(
            extract(hard_link, &hard_link_dest).await.unwrap_err(),
            DecodeError::PolicyViolation {
                position: 0,
                violation: DecodePolicyViolation::HardLink,
            }
        ));
        assert!(!hard_link_dest.join("link").exists());
    }

    #[tokio::test]
    async fn rejects_gnu_archives_when_policy_requires_posix_pax() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_gnu_member(&mut bytes, "longname", b'L', b"renamed\0", "", 0o644);
        append_gnu_member(&mut bytes, "raw", b'0', b"contents", "", 0o644);
        finish(&mut bytes);

        assert!(matches!(
            extract_with_policy(bytes, &dest, DecodePolicy::default().allow_gnu(false))
                .await
                .unwrap_err(),
            DecodeError::PolicyViolation {
                position: 0,
                violation: DecodePolicyViolation::GnuArchive,
            }
        ));
        assert!(!dest.join("renamed").exists());

        let empty_dest = temp.path().join("empty");
        let mut empty = Vec::new();
        finish(&mut empty);
        extract_with_policy(empty, &empty_dest, DecodePolicy::default().allow_gnu(false))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_every_pax_vendor_record_when_otherwise_permitted() {
        let temp = tempdir().unwrap();
        for (case, typeflag, payload) in [
            ("local", b'x', record("ACME.attribute", "value")),
            ("active-global", b'g', record("ACME.attribute", "value")),
            ("deleted-global", b'g', record("ACME.attribute", "")),
            ("replaced-global", b'g', {
                let mut payload = record("ACME.attribute", "value");
                payload.extend_from_slice(&record("ACME.attribute", ""));
                payload
            }),
        ] {
            let dest = temp.path().join(case);
            let mut bytes = Vec::new();
            append_pax(&mut bytes, typeflag, &payload);
            append_posix_member(&mut bytes, "file", b'0', b"", "", 0o644);
            finish(&mut bytes);
            assert!(matches!(
                extract_with_policy(
                    bytes,
                    &dest,
                    DecodePolicy::default().pax_policy(
                        PaxDecodePolicy::default().allow_global_pax_extensions(typeflag == b'g')
                    )
                )
                .await
                .unwrap_err(),
                DecodeError::PolicyViolation {
                    position: 0,
                    violation: DecodePolicyViolation::PaxVendorExtension {
                        vendor,
                        name
                    },
                } if vendor == "ACME" && name == "attribute"
            ));
        }
    }

    #[tokio::test]
    async fn vendor_policy_reports_source_position_preserves_output_and_allows_opt_in() {
        let temp = tempdir().unwrap();
        let partial_dest = temp.path().join("partial");
        let mut partial = Vec::new();
        append_posix_member(&mut partial, "created", b'0', b"kept", "", 0o644);
        append_pax(&mut partial, b'g', &record("ACME.attribute", "value"));
        append_posix_member(&mut partial, "blocked", b'0', b"", "", 0o644);
        finish(&mut partial);
        assert!(matches!(
            extract_with_policy(
                partial,
                &partial_dest,
                DecodePolicy::default()
                    .pax_policy(PaxDecodePolicy::default().allow_global_pax_extensions(true))
            )
            .await
            .unwrap_err(),
            DecodeError::PolicyViolation {
                position: 1024,
                violation: DecodePolicyViolation::PaxVendorExtension { .. },
            }
        ));
        assert_eq!(
            std::fs::read_to_string(partial_dest.join("created")).unwrap(),
            "kept"
        );

        let permitted_dest = temp.path().join("permitted");
        let mut permitted = Vec::new();
        append_pax(&mut permitted, b'x', &record("ACME.attribute", "value"));
        append_posix_member(&mut permitted, "file", b'0', b"ok", "", 0o644);
        finish(&mut permitted);
        extract_with_policy(
            permitted,
            &permitted_dest,
            DecodePolicy::default()
                .pax_policy(PaxDecodePolicy::default().allow_pax_vendor_extensions(true)),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(permitted_dest.join("file")).unwrap(),
            "ok"
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_pax_records_by_default_and_can_apply_last_value() {
        let temp = tempdir().unwrap();
        let mut local = record("path", "wrong");
        local.extend_from_slice(&record("path", "actual"));

        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'x', &local);
        append_posix_member(&mut bytes, "raw", b'0', b"contents", "", 0o644);
        finish(&mut bytes);

        let rejected_dest = temp.path().join("rejected");
        assert!(matches!(
            extract(bytes.clone(), &rejected_dest).await.unwrap_err(),
            DecodeError::PolicyViolation {
                position: 0,
                violation: DecodePolicyViolation::DuplicatePaxRecord { keyword },
            } if keyword == "path"
        ));
        assert!(!rejected_dest.join("actual").exists());

        let permitted_dest = temp.path().join("permitted");
        extract_with_policy(
            bytes,
            &permitted_dest,
            DecodePolicy::default()
                .pax_policy(PaxDecodePolicy::default().allow_duplicate_pax_records(true)),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(permitted_dest.join("actual")).unwrap(),
            "contents"
        );
        assert!(!permitted_dest.join("wrong").exists());
    }

    #[tokio::test]
    async fn allows_harmless_global_pax_extensions_by_default_and_supports_opt_out() {
        let temp = tempdir().unwrap();
        let rejected_dest = temp.path().join("rejected");
        let mut rejected = Vec::new();
        append_pax(&mut rejected, b'g', &record("comment", "metadata"));
        append_posix_member(&mut rejected, "file", b'0', b"", "", 0o644);
        finish(&mut rejected);
        assert!(matches!(
            extract_with_policy(
                rejected,
                &rejected_dest,
                DecodePolicy::default()
                    .pax_policy(PaxDecodePolicy::default().allow_global_pax_extensions(false))
            )
            .await
            .unwrap_err(),
            DecodeError::PolicyViolation {
                position: 0,
                violation: DecodePolicyViolation::GlobalPaxExtension,
            }
        ));

        let permitted_dest = temp.path().join("permitted");
        let mut permitted = Vec::new();
        append_pax(&mut permitted, b'g', &record("comment", "metadata"));
        append_posix_member(&mut permitted, "file", b'0', b"contents", "", 0o644);
        finish(&mut permitted);
        extract(permitted, &permitted_dest).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(permitted_dest.join("file")).unwrap(),
            "contents"
        );
    }

    #[tokio::test]
    async fn ignores_trailing_global_pax_but_reports_framing_errors_before_policy() {
        let temp = tempdir().unwrap();
        let policy = DecodePolicy::default()
            .pax_policy(PaxDecodePolicy::default().allow_global_pax_extensions(false));

        let mut trailing = Vec::new();
        append_pax(&mut trailing, b'g', &record("comment", "metadata"));
        finish(&mut trailing);
        extract_with_policy(trailing, &temp.path().join("trailing"), policy)
            .await
            .unwrap();

        let mut malformed = Vec::new();
        append_pax(&mut malformed, b'g', b"invalid");
        finish(&mut malformed);
        assert!(matches!(
            extract_with_policy(malformed, &temp.path().join("malformed"), policy)
                .await
                .unwrap_err(),
            DecodeError::Framing(FrameError {
                position: 0,
                inner: FrameErrorInner::InvalidPaxRecords { .. },
            })
        ));

        let mut missing_end = Vec::new();
        append_pax(&mut missing_end, b'g', &record("comment", "metadata"));
        assert!(matches!(
            extract_with_policy(missing_end, &temp.path().join("missing-end"), policy)
                .await
                .unwrap_err(),
            DecodeError::Framing(FrameError {
                inner: FrameErrorInner::MissingEndMarker,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn allows_global_member_metadata_updates_when_enabled() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'g', &record("path", "old"));
        append_pax(&mut bytes, b'g', &record("path", "current"));
        append_posix_member(&mut bytes, "raw", b'0', b"contents", "", 0o644);
        finish(&mut bytes);

        extract_with_policy(
            bytes,
            &dest,
            DecodePolicy::default().pax_policy(
                PaxDecodePolicy::default()
                    .allow_global_pax_extensions(true)
                    .allow_global_pax_member_metadata(true),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("current")).unwrap(),
            "contents"
        );
        assert!(!dest.join("old").exists());
    }

    #[tokio::test]
    async fn global_path_deletion_suppresses_the_physical_header_path_when_enabled() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'g', &record("path", ""));
        append_posix_member(&mut bytes, "physical", b'0', b"", "", 0o644);
        finish(&mut bytes);

        assert!(matches!(
            extract_with_policy(
                bytes,
                &dest,
                DecodePolicy::default().pax_policy(
                    PaxDecodePolicy::default()
                        .allow_global_pax_extensions(true)
                        .allow_global_pax_member_metadata(true),
                ),
            )
            .await
            .unwrap_err(),
            DecodeError::Framing(FrameError {
                inner: FrameErrorInner::DeletedPaxMetadata { keyword: "path" },
                ..
            })
        ));
        assert!(!dest.join("physical").exists());
    }

    #[tokio::test]
    async fn rejects_member_specific_global_pax_records_when_global_extensions_are_allowed() {
        let temp = tempdir().unwrap();
        for (case, keyword, value) in [
            ("path", "path", "file"),
            ("linkpath", "linkpath", "target"),
            ("size", "size", "0"),
            ("deleted-path", "path", ""),
        ] {
            let dest = temp.path().join(case);
            let mut bytes = Vec::new();
            append_pax(&mut bytes, b'g', &record(keyword, value));
            append_posix_member(&mut bytes, "raw", b'0', b"", "", 0o644);
            finish(&mut bytes);

            assert!(matches!(
                extract_with_policy(
                    bytes,
                    &dest,
                    DecodePolicy::default()
                        .pax_policy(PaxDecodePolicy::default().allow_global_pax_extensions(true))
                )
                .await
                .unwrap_err(),
                DecodeError::PolicyViolation {
                    position: 0,
                    violation: DecodePolicyViolation::GlobalPaxMemberMetadata {
                        keyword: found,
                    },
                } if found == keyword
            ));
        }
    }

    #[tokio::test]
    async fn rejects_invalid_extension_text_and_preserves_partial_outputs() {
        let temp = tempdir().unwrap();

        let mut deleted = Vec::new();
        append_pax(&mut deleted, b'x', &record("path", ""));
        append_posix_member(&mut deleted, "raw", b'0', b"", "", 0o644);
        finish(&mut deleted);

        let mut binary_path = record("hdrcharset", "BINARY");
        binary_path.extend_from_slice(&raw_record("path", &[0xff]));
        let mut binary = Vec::new();
        append_pax(&mut binary, b'x', &binary_path);
        append_posix_member(&mut binary, "raw", b'0', b"", "", 0o644);
        finish(&mut binary);

        let mut malformed_gnu = Vec::new();
        append_gnu_member(&mut malformed_gnu, "longname", b'L', b"no-nul", "", 0o644);
        append_gnu_member(&mut malformed_gnu, "raw", b'0', b"", "", 0o644);
        finish(&mut malformed_gnu);

        let mut invalid_utf8 = header(POSIX_IDENTITY, "name", b'0', 0, "", 0o644);
        invalid_utf8[NAME_RANGE.start] = 0xff;
        set_checksum(&mut invalid_utf8);
        let mut invalid_utf8_archive = invalid_utf8.to_vec();
        finish(&mut invalid_utf8_archive);

        let mut invalid_mode = header(POSIX_IDENTITY, "mode", b'0', 0, "", 0o644);
        invalid_mode[MODE_RANGE].copy_from_slice(b"0000080\0");
        set_checksum(&mut invalid_mode);
        let mut invalid_mode_archive = invalid_mode.to_vec();
        finish(&mut invalid_mode_archive);

        for (case, bytes, expected) in [
            (
                "deleted",
                deleted,
                (|error| {
                    matches!(
                        error,
                        DecodeError::Framing(FrameError {
                            inner: FrameErrorInner::DeletedPaxMetadata { keyword: "path" },
                            ..
                        })
                    )
                }) as DecodeErrorMatcher,
            ),
            ("binary", binary, |error| {
                matches!(error, DecodeError::InvalidUtf8 { field: "path", .. })
            }),
            ("gnu", malformed_gnu, |error| {
                matches!(
                    error,
                    DecodeError::Framing(FrameError {
                        inner: FrameErrorInner::InvalidGnuMetadata { .. },
                        ..
                    })
                )
            }),
            ("utf8", invalid_utf8_archive, |error| {
                matches!(error, DecodeError::InvalidUtf8 { .. })
            }),
            ("mode", invalid_mode_archive, |error| {
                matches!(
                    error,
                    DecodeError::Framing(FrameError {
                        inner: FrameErrorInner::InvalidMode { .. },
                        ..
                    })
                )
            }),
        ] {
            let dest = temp.path().join(case);
            let error = extract(bytes, &dest).await.unwrap_err();
            assert!(expected(&error), "{case}: {error:?}");
        }

        let partial_dest = temp.path().join("partial");
        let mut partial = Vec::new();
        append_posix_member(&mut partial, "created", b'0', b"kept", "", 0o644);
        let mut invalid = header(POSIX_IDENTITY, "bad", b'0', 0, "", 0o644);
        invalid[IDENTITY_RANGE.start] = b'!';
        set_checksum(&mut invalid);
        append_block(&mut partial, &invalid);
        let error = extract(partial, &partial_dest).await.unwrap_err();
        assert!(matches!(error, DecodeError::Framing(_)));
        assert_eq!(
            std::fs::read_to_string(partial_dest.join("created")).unwrap(),
            "kept"
        );
    }
}
