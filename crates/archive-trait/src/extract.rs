//! Format-neutral archive extraction.

use std::{
    collections::{HashMap, HashSet},
    fs as std_fs,
    marker::PhantomData,
    path::Component,
    sync::Arc,
};

use super::*;
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

/// Controls generic archive extraction behavior.
///
/// See each configuration API for its default.
#[derive(Clone, Copy, Debug)]
pub struct ExtractPolicy {
    pub(crate) link_policy: LinkPolicy,
    pub(crate) allow_overwrites: bool,
    pub(crate) name_validation: crate::name::NameValidation,
}

/// Controls how symbolic- and hard-link members are extracted.
///
/// By default, symbolic links are preserved as native links, including links
/// to missing targets. Hard links and ambient symbolic-link targets require
/// explicit opt-in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkPolicy {
    pub(crate) symlink_policy: SymlinkPolicy,
    pub(crate) allow_hard_links: bool,
    pub(crate) allow_ambient_targets: bool,
    pub(crate) allow_missing_targets: bool,
}

/// Controls how symbolic-link members are handled during extraction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SymlinkPolicy {
    /// Preserve symbolic-link members as native filesystem links.
    #[default]
    Preserve,
    /// Ignore symbolic-link members without changing the filesystem.
    Skip,
    /// Reject archives containing symbolic-link members.
    Reject,
}

impl Default for ExtractPolicy {
    fn default() -> Self {
        Self {
            link_policy: LinkPolicy::default(),
            allow_overwrites: true,
            name_validation: crate::name::NameValidation::Default,
        }
    }
}

impl Default for LinkPolicy {
    fn default() -> Self {
        Self {
            symlink_policy: SymlinkPolicy::default(),
            allow_hard_links: false,
            allow_ambient_targets: false,
            allow_missing_targets: true,
        }
    }
}

impl ExtractPolicy {
    /// Configures symbolic- and hard-link extraction behavior.
    pub fn link_policy(mut self, policy: LinkPolicy) -> Self {
        self.link_policy = policy;
        self
    }

    /// Configures whether archive members may replace existing entries.
    ///
    /// Overwrites are **allowed by default**. Replacement never follows
    /// symbolic links or recursively removes non-empty directories. Real
    /// directories are always reused, including when overwrites are disabled.
    pub fn allow_overwrites(mut self, allow: bool) -> Self {
        self.allow_overwrites = allow;
        self
    }

    /// Configures validation for member names and link targets.
    ///
    /// Passing [`None`] disables configurable name validation. UTF-8 and
    /// extraction containment requirements still apply.
    pub fn name_validator(mut self, validator: Option<NameValidator>) -> Self {
        self.name_validation = crate::name::NameValidation::from_validator(validator);
        self
    }

    fn check_name<E>(
        self,
        position: u64,
        context: &'static str,
        value: &str,
    ) -> Result<(), ExtractError<E>> {
        if !self.name_validation.accepts(value) {
            return Err(ExtractError::policy_violation(
                position,
                ExtractPolicyViolation::NameRejected {
                    context,
                    value: value.to_owned(),
                },
            ));
        }
        Ok(())
    }
}

impl LinkPolicy {
    /// Configures how symbolic-link members are handled during extraction.
    ///
    /// Symbolic links are preserved by default. Platforms without native
    /// symbolic-link creation require [`SymlinkPolicy::Skip`] or
    /// [`SymlinkPolicy::Reject`].
    pub fn symlink_policy(mut self, policy: SymlinkPolicy) -> Self {
        self.symlink_policy = policy;
        self
    }

    /// Configures whether hard-link members may be extracted.
    ///
    /// Hard links are **forbidden by default** because they are uncommon,
    /// difficult to extract consistently, and prone to implementation
    /// differentials. Enable them only for trusted archives.
    pub fn allow_hard_links(mut self, allow: bool) -> Self {
        self.allow_hard_links = allow;
        self
    }

    /// Configures whether pre-existing symbolic-link targets may be used.
    ///
    /// Existing symbolic links are followed only when capability-relative
    /// resolution remains beneath the extraction root. Ambient targets are
    /// **forbidden by default**. This does not affect hard-link validation.
    pub fn allow_ambient_targets(mut self, allow: bool) -> Self {
        self.allow_ambient_targets = allow;
        self
    }

    /// Configures whether symbolic links to missing targets may be extracted.
    ///
    /// Missing symbolic-link targets are **allowed by default**. This does not
    /// affect hard-link validation.
    pub fn allow_missing_targets(mut self, allow: bool) -> Self {
        self.allow_missing_targets = allow;
        self
    }
}

/// A symbolic link awaiting graph validation and final extraction.
///
/// [`PendingSymlink::target`] preserves the archive text for optional native
/// installation, while [`PendingSymlink::resolved_target`] is used to validate
/// the archive's symbolic-link graph relative to the extraction root.
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

/// Represents a root directory for an extraction operation.
struct ExtractionRoot<E> {
    /// The capability anchoring all extraction filesystem operations.
    directory: Arc<Dir>,
    /// Capabilities for known directories, used to keep leaf operations cheap.
    directory_handles: HashMap<PathBuf, Arc<Dir>>,
    /// Whether overwrites are allowed during extraction.
    allow_overwrites: bool,
    entries: HashMap<PathBuf, ExtractedEntry>,
    symlink_indices: HashMap<PathBuf, usize>,
    symlinks: Vec<PendingSymlink>,
    error: PhantomData<fn() -> E>,
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

pub(crate) async fn extract<A: Archive>(
    mut members: Members<A>,
    destination: &Path,
    policy: ExtractPolicy,
) -> Result<(), ExtractError<A::Error>> {
    let mut root = ExtractionRoot::<A::Error>::open(destination, policy.allow_overwrites).await?;
    // Scratch space reused for each payload read and streamed directly for large files.
    let mut chunk_buffer = Vec::new();
    // Complete small-file contents, buffered so payload validation precedes file creation.
    let mut buffered_payload = Vec::new();
    while let Some(member) = members.next().await.map_err(ExtractError::Archive)? {
        check_member_policy(&member, policy)?;
        let decoded = decode_member(&member, policy)?;
        match member {
            Member::File {
                size,
                executable,
                payload,
                ..
            } => {
                root.extract_file(
                    &decoded.path,
                    size,
                    executable,
                    payload,
                    &mut chunk_buffer,
                    &mut buffered_payload,
                )
                .await?;
            }
            Member::Directory { .. } => root.extract_directory(&decoded.path).await?,
            Member::SymbolicLink { .. } => {
                if policy.link_policy.symlink_policy == SymlinkPolicy::Preserve {
                    root.reserve_symlink(&decoded).await?;
                }
            }
            Member::HardLink { size, payload, .. } => {
                root.extract_hard_link(&decoded, size, payload, &mut chunk_buffer)
                    .await?;
            }
            Member::Special { kind, .. } => {
                return Err(ExtractError::UnsupportedMember {
                    position: decoded.position,
                    path: decoded.path,
                    kind,
                });
            }
        }
    }
    root.finalize_symlinks(policy.link_policy).await
}

fn check_member_policy<E, P>(
    member: &Member<P>,
    policy: ExtractPolicy,
) -> Result<(), ExtractError<E>> {
    let position = member.metadata().position;
    match member {
        Member::SymbolicLink { .. } => {
            let violation = match policy.link_policy.symlink_policy {
                SymlinkPolicy::Reject => Some(ExtractPolicyViolation::SymbolicLink),
                #[cfg(not(unix))]
                SymlinkPolicy::Preserve => {
                    Some(ExtractPolicyViolation::NativeSymlinkCreationUnsupported)
                }
                _ => None,
            };
            if let Some(violation) = violation {
                return Err(ExtractError::policy_violation(position, violation));
            }
        }
        Member::HardLink { .. } if !policy.link_policy.allow_hard_links => {
            return Err(ExtractError::policy_violation(
                position,
                ExtractPolicyViolation::HardLink,
            ));
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug)]
struct ExtractMember {
    position: u64,
    path: PathBuf,
    link_target: String,
}

fn decode_member<E, P>(
    member: &Member<P>,
    policy: ExtractPolicy,
) -> Result<ExtractMember, ExtractError<E>> {
    let metadata = member.metadata();
    policy.check_name(metadata.position, "member path", &metadata.path)?;

    if !matches!(member, Member::Directory { .. })
        && (metadata.path.ends_with('/')
            || metadata
                .path
                .rsplit_once('/')
                .is_some_and(|(_, component)| matches!(component, "." | "..")))
    {
        return Err(ExtractError::unsafe_path(
            metadata.position,
            "member path",
            &metadata.path,
            "only a directory may have a directory-required path suffix",
        ));
    }
    let path = normalize_member_path(metadata.position, &metadata.path)?;
    if path.as_os_str().is_empty() && !matches!(member, Member::Directory { .. }) {
        return Err(ExtractError::unsafe_path(
            metadata.position,
            "member path",
            &metadata.path,
            "only a directory may resolve to the extraction root",
        ));
    }
    let link_target = match member {
        Member::SymbolicLink { target, .. } => {
            policy.check_name(metadata.position, "symbolic-link target", target)?;
            target
        }
        Member::HardLink { target, .. } => {
            policy.check_name(metadata.position, "hard-link target", target)?;
            target
        }
        _ => "",
    };
    if link_target.is_empty()
        && matches!(
            member,
            Member::SymbolicLink { .. } | Member::HardLink { .. }
        )
    {
        return Err(ExtractError::invalid_link(
            metadata.position,
            path,
            link_target.to_owned(),
            "link target is empty",
        ));
    }
    Ok(ExtractMember {
        position: metadata.position,
        path,
        link_target: link_target.to_owned(),
    })
}

fn normalize_member_path<E>(position: u64, value: &str) -> Result<PathBuf, ExtractError<E>> {
    validate_extraction_path(position, "member path", value)?;
    let mut path = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Prefix(_) => {
                return Err(ExtractError::unsafe_path(
                    position,
                    "member path",
                    value,
                    "contains a platform path prefix",
                ));
            }
            Component::RootDir => {
                return Err(ExtractError::unsafe_path(
                    position,
                    "member path",
                    value,
                    "is absolute",
                ));
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(ExtractError::unsafe_path(
                    position,
                    "member path",
                    value,
                    "contains a parent-directory component",
                ));
            }
            Component::Normal(component) => path.push(component),
        }
    }
    Ok(path)
}

struct ValidatedSymlinkTarget {
    resolved_target: PathBuf,
    requires_directory: bool,
}

fn validate_symlink_target<E>(
    position: u64,
    path: &Path,
    value: &str,
) -> Result<ValidatedSymlinkTarget, ExtractError<E>> {
    validate_extraction_path(position, "symbolic-link target", value)?;
    let base = path.parent().unwrap_or_else(|| Path::new(""));
    let mut resolved = base.to_owned();
    let mut normal_component_seen = false;
    for component in Path::new(value).components() {
        match component {
            Component::Prefix(_) => {
                return Err(ExtractError::unsafe_path(
                    position,
                    "symbolic-link target",
                    value,
                    "contains a platform path prefix",
                ));
            }
            Component::RootDir => {
                return Err(ExtractError::unsafe_path(
                    position,
                    "symbolic-link target",
                    value,
                    "is absolute",
                ));
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if normal_component_seen {
                    return Err(ExtractError::unsafe_path(
                        position,
                        "symbolic-link target",
                        value,
                        "contains ambiguous parent-directory traversal",
                    ));
                }
                if !resolved.pop() {
                    return Err(ExtractError::unsafe_path(
                        position,
                        "symbolic-link target",
                        value,
                        "escapes the destination root",
                    ));
                }
            }
            Component::Normal(component) => {
                normal_component_seen = true;
                resolved.push(component);
            }
        }
    }
    Ok(ValidatedSymlinkTarget {
        resolved_target: resolved,
        requires_directory: value.ends_with('/')
            || matches!(value.rsplit('/').next(), Some("." | "..")),
    })
}

fn validate_extraction_path<E>(
    position: u64,
    context: &'static str,
    value: &str,
) -> Result<(), ExtractError<E>> {
    if value.contains('\\') {
        return Err(ExtractError::unsafe_path(
            position,
            context,
            value,
            "contains a backslash separator",
        ));
    }
    if value.starts_with('/') {
        return Err(ExtractError::unsafe_path(
            position,
            context,
            value,
            "is absolute",
        ));
    }
    Ok(())
}

fn resolve_link_target<E>(
    position: u64,
    context: &'static str,
    value: &str,
    base: &Path,
) -> Result<PathBuf, ExtractError<E>> {
    validate_extraction_path(position, context, value)?;
    let mut path = base.to_owned();
    for component in Path::new(value).components() {
        match component {
            Component::Prefix(_) => {
                return Err(ExtractError::unsafe_path(
                    position,
                    context,
                    value,
                    "contains a platform path prefix",
                ));
            }
            Component::RootDir => {
                return Err(ExtractError::unsafe_path(
                    position,
                    context,
                    value,
                    "is absolute",
                ));
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !path.pop() {
                    return Err(ExtractError::unsafe_path(
                        position,
                        context,
                        value,
                        "escapes the destination root",
                    ));
                }
            }
            Component::Normal(component) => path.push(component),
        }
    }
    Ok(path)
}

async fn write_payload<P: MemberPayload>(
    mut payload: P,
    chunk_buffer: &mut Vec<u8>,
    path: &Path,
    mut file: File,
) -> Result<(), ExtractError<P::Error>> {
    loop {
        chunk_buffer.clear();
        if !payload
            .next_chunk(chunk_buffer, EXTRACTION_CHUNK_BYTES)
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

impl<E> ExtractionRoot<E> {
    async fn open(dest: &Path, allow_overwrites: bool) -> Result<Self, ExtractError<E>> {
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
        .map_err(ExtractError::<E>::BlockingTask)?
        .map_err(|source| {
            ExtractError::<E>::filesystem("open destination directory", error_path, source)
        })?;

        Ok(Self {
            directory,
            directory_handles: HashMap::new(),
            allow_overwrites,
            entries: HashMap::new(),
            symlink_indices: HashMap::new(),
            symlinks: Vec::new(),
            error: PhantomData,
        })
    }

    async fn extract_file<P: MemberPayload<Error = E>>(
        &mut self,
        path: &Path,
        size: u64,
        executable: bool,
        mut payload: P,
        chunk_buffer: &mut Vec<u8>,
        buffered_payload: &mut Vec<u8>,
    ) -> Result<(), ExtractError<E>> {
        if size <= EXTRACTION_CHUNK_BYTES as u64 {
            buffered_payload.clear();
            if let Ok(payload_size) = usize::try_from(size) {
                buffered_payload.reserve(payload_size);
            }
            loop {
                chunk_buffer.clear();
                if !payload
                    .next_chunk(chunk_buffer, EXTRACTION_CHUNK_BYTES)
                    .await
                    .map_err(ExtractError::Archive)?
                {
                    break;
                }
                buffered_payload.extend_from_slice(chunk_buffer);
            }
            let mut file = self.create_file(path, executable).await?;
            file.write_all(buffered_payload).await.map_err(|source| {
                ExtractError::filesystem("write file", path.to_owned(), source)
            })?;
            file.flush().await.map_err(|source| {
                ExtractError::filesystem("flush file", path.to_owned(), source)
            })?;
            return Ok(());
        }
        let file = self.create_file(path, executable).await?;
        write_payload(payload, chunk_buffer, path, file).await
    }

    async fn extract_directory(&mut self, path: &Path) -> Result<(), ExtractError<E>> {
        if !path.as_os_str().is_empty() {
            self.ensure_parents(path).await?;
            self.ensure_directory(path, DirectoryPurpose::ExplicitMember)
                .await?;
        }
        Ok(())
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

    async fn reserve_symlink(&mut self, member: &ExtractMember) -> Result<(), ExtractError<E>> {
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

    async fn extract_hard_link<P: MemberPayload<Error = E>>(
        &mut self,
        member: &ExtractMember,
        size: u64,
        payload: P,
        chunk_buffer: &mut Vec<u8>,
    ) -> Result<(), ExtractError<E>> {
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
        if size == 0 {
            payload.skip().await.map_err(ExtractError::Archive)?;
            Ok(())
        } else {
            let file = self
                .open_file("truncate file", &member.path, false, true, false)
                .await?;
            write_payload(payload, chunk_buffer, &member.path, file).await
        }
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
        if let Some(entry) = self.entries.get(path).copied()
            && entry.is_directory()
        {
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
        if purpose == DirectoryPurpose::ImplicitParent {
            return Err(ExtractError::<E>::PathCollision {
                path: path.to_owned(),
            });
        }
        self.replace_leaf(path).await?;
        let directory = self.create_directory(path).await?;
        self.directory_handles
            .insert(path.to_owned(), Arc::new(directory));
        self.entries
            .insert(path.to_owned(), ExtractedEntry::CreatedDirectory);
        Ok(())
    }

    async fn replace_leaf(&mut self, path: &Path) -> Result<bool, ExtractError<E>> {
        let metadata = self.metadata(path).await?;
        if metadata.is_none() && !self.entries.contains_key(path) {
            return Ok(false);
        }
        if !self.allow_overwrites || self.has_descendant(path) {
            return Err(ExtractError::<E>::PathCollision {
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

    async fn finalize_symlinks(&self, policy: LinkPolicy) -> Result<(), ExtractError<E>> {
        let mut links = Vec::with_capacity(self.symlinks.len());
        for (index, link) in self.symlinks.iter().enumerate() {
            if self.symlink_indices.get(&link.path) != Some(&index) {
                continue;
            }
            let target = self
                .resolve_terminal(&link.resolved_target)
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

    fn resolve_terminal(&self, path: &Path) -> Result<ResolvedTarget, &'static str> {
        let mut path = path.to_owned();
        let mut visited = HashSet::new();
        for _ in 0..=MAX_SYMLINK_EXPANSIONS {
            if !visited.insert(path.clone()) {
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
                path = rewritten;
            } else {
                return Ok(match self.entries.get(&path) {
                    _ if path.as_os_str().is_empty() => {
                        ResolvedTarget::Known(TerminalKind::Directory)
                    }
                    Some(ExtractedEntry::CreatedDirectory) => {
                        ResolvedTarget::Known(TerminalKind::Directory)
                    }
                    Some(ExtractedEntry::File) => ResolvedTarget::Known(TerminalKind::NonDirectory),
                    Some(ExtractedEntry::Symlink) => continue,
                    Some(ExtractedEntry::AmbientDirectory) | None => ResolvedTarget::Unowned(path),
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
                .with_entry_parent("inspect directory", path, |root, path| {
                    let directory = root.open_dir(path)?;
                    let mut entries = directory.entries()?;
                    Ok(entries.next().transpose()?.is_none())
                })
                .await?;
            if !is_empty {
                return Err(ExtractError::<E>::PathCollision {
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
    ) -> Result<File, ExtractError<E>> {
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

    async fn create_directory(&self, path: &Path) -> Result<Dir, ExtractError<E>> {
        self.with_entry_parent("create directory", path, |directory, path| {
            directory.create_dir(path)?;
            directory.open_dir(path)
        })
        .await
    }

    async fn open_directory(&self, path: &Path) -> Result<Dir, ExtractError<E>> {
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
/// without losing useful [`ExtractError::Filesystem`] context.
///
/// Filesystem errors are annotated with `operation` and `error_path`, while a
/// failure to join the blocking task becomes [`ExtractError::BlockingTask`].
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
