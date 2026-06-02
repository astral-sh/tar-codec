//! Secure high-level decoding and extraction for validated tar streams.
//!
//! `tar-codec` interprets member metadata above [`tar_framing`] and extracts
//! archive contents into a capability-scoped destination. Decompression is the
//! caller's responsibility. Extraction requires an [`ExtractPolicy`] so that
//! security-sensitive archive features are explicit at each call site.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    io::{self, Write},
    mem,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use tar_framing::{
    ArchiveFormat, FrameError, MemberKind, PaxKind, PaxRecord,
    logical::{LogicalFrame, MemberExtensions, MemberFrame, MemberHeader, TarReader},
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWriteExt};

use crate::blocking::with_reusable_buffer;

const EXTRACTION_CHUNK_BYTES: usize = 1024 * 1024;

/// A one-pass reader for a validated pax or GNU tar archive.
pub struct Archive<R> {
    reader: TarReader<R>,
}

impl<R> Archive<R> {
    /// Creates an archive decoder from an uncompressed tar reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader: TarReader::new(reader),
        }
    }
}

/// Controls which otherwise valid archive features extraction may accept.
///
/// The default permits symbolic links, safe dangling symbolic links, and
/// either supported framing family, while rejecting hard links, global pax
/// member metadata, vendor-namespaced pax records, and repeated keywords.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodePolicy {
    allow_symlinks: bool,
    allow_dangling_symlinks: bool,
    allow_hard_links: bool,
    allow_gnu: bool,
    pax_policy: PaxDecodePolicy,
}

/// Controls which otherwise valid pax features extraction may accept.
///
/// The default permits global pax extension headers while rejecting global
/// per-member metadata, vendor-namespaced records, and duplicate records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaxDecodePolicy {
    allow_global_pax_extensions: bool,
    allow_pax_vendor_extensions: bool,
    allow_duplicate_pax_records: bool,
    allow_global_pax_member_metadata: bool,
}

impl Default for PaxDecodePolicy {
    fn default() -> Self {
        Self {
            allow_global_pax_extensions: true,
            allow_pax_vendor_extensions: false,
            allow_duplicate_pax_records: false,
            allow_global_pax_member_metadata: false,
        }
    }
}

impl Default for DecodePolicy {
    fn default() -> Self {
        Self {
            allow_symlinks: true,
            allow_dangling_symlinks: true,
            allow_hard_links: false,
            allow_gnu: true,
            pax_policy: PaxDecodePolicy::default(),
        }
    }
}

impl DecodePolicy {
    /// Configures whether symbolic-link members may be extracted.
    pub fn allow_symlinks(mut self, allow: bool) -> Self {
        self.allow_symlinks = allow;
        self
    }

    /// Configures whether symbolic links may name safe targets other than
    /// entries created by this extraction or the extraction root.
    pub fn allow_dangling_symlinks(mut self, allow: bool) -> Self {
        self.allow_dangling_symlinks = allow;
        self
    }

    /// Configures whether hard-link members may be extracted.
    ///
    /// When enabled, pax `linkdata` payloads may update the contents of an
    /// earlier extracted file through its shared inode. Hard-link headers with
    /// modes different from their targets are accepted without changing the
    /// shared inode mode.
    pub fn allow_hard_links(mut self, allow: bool) -> Self {
        self.allow_hard_links = allow;
        self
    }

    /// Configures whether archives in the GNU framing family may be extracted.
    pub fn allow_gnu(mut self, allow: bool) -> Self {
        self.allow_gnu = allow;
        self
    }

    /// Configures the accepted pax feature subset.
    pub fn pax_policy(mut self, policy: PaxDecodePolicy) -> Self {
        self.pax_policy = policy;
        self
    }

    fn check_format(&self, position: u64, format: ArchiveFormat) -> Result<(), DecodeError> {
        if format == ArchiveFormat::Gnu && !self.allow_gnu {
            return Err(policy_violation(
                position,
                DecodePolicyViolation::GnuArchive,
            ));
        }
        Ok(())
    }

    fn check_member_kind(&self, position: u64, kind: MemberKind) -> Result<(), DecodeError> {
        let violation = match kind {
            MemberKind::SymbolicLink if !self.allow_symlinks => {
                Some(DecodePolicyViolation::SymbolicLink)
            }
            MemberKind::HardLink if !self.allow_hard_links => Some(DecodePolicyViolation::HardLink),
            _ => None,
        };
        if let Some(violation) = violation {
            return Err(policy_violation(position, violation));
        }
        Ok(())
    }
}

impl PaxDecodePolicy {
    /// Configures whether global pax extension headers may be accepted.
    ///
    /// When enabled, [`Self::allow_global_pax_member_metadata`] separately
    /// controls whether global `path`, `linkpath`, and `size` records are
    /// accepted.
    pub fn allow_global_pax_extensions(mut self, allow: bool) -> Self {
        self.allow_global_pax_extensions = allow;
        self
    }

    /// Configures whether vendor-namespaced pax records may be accepted.
    pub fn allow_pax_vendor_extensions(mut self, allow: bool) -> Self {
        self.allow_pax_vendor_extensions = allow;
        self
    }

    /// Configures whether one pax extended header may repeat a keyword.
    ///
    /// When enabled, standard pax precedence applies and the last record for
    /// a repeated keyword takes effect.
    pub fn allow_duplicate_pax_records(mut self, allow: bool) -> Self {
        self.allow_duplicate_pax_records = allow;
        self
    }

    /// Configures whether global pax headers may set member path or size data.
    ///
    /// When enabled, standard pax semantics permit global `path`, `linkpath`,
    /// and `size` records to apply to following members until overridden.
    pub fn allow_global_pax_member_metadata(mut self, allow: bool) -> Self {
        self.allow_global_pax_member_metadata = allow;
        self
    }

    fn check_global_pax_extension(&self, position: u64) -> Result<(), DecodeError> {
        if !self.allow_global_pax_extensions {
            return Err(policy_violation(
                position,
                DecodePolicyViolation::GlobalPaxExtension,
            ));
        }
        Ok(())
    }

    fn check_pax_records(
        &self,
        position: u64,
        kind: PaxKind,
        records: &[PaxRecord],
    ) -> Result<(), DecodeError> {
        if !self.allow_pax_vendor_extensions {
            for record in records {
                if let PaxRecord::Vendor { vendor, name, .. } = record {
                    return Err(policy_violation(
                        position,
                        DecodePolicyViolation::PaxVendorExtension {
                            vendor: vendor.clone(),
                            name: name.clone(),
                        },
                    ));
                }
            }
        }

        if kind == PaxKind::Global && !self.allow_global_pax_member_metadata {
            for record in records {
                let keyword = match record {
                    PaxRecord::Path(_) => Some("path"),
                    PaxRecord::LinkPath(_) => Some("linkpath"),
                    PaxRecord::Size(_) => Some("size"),
                    _ => None,
                };
                if let Some(keyword) = keyword {
                    return Err(policy_violation(
                        position,
                        DecodePolicyViolation::GlobalPaxMemberMetadata { keyword },
                    ));
                }
            }
        }

        if !self.allow_duplicate_pax_records {
            let mut keywords = HashSet::new();
            for record in records {
                let keyword = record.keyword().into_owned();
                if !keywords.insert(keyword.clone()) {
                    return Err(policy_violation(
                        position,
                        DecodePolicyViolation::DuplicatePaxRecord { keyword },
                    ));
                }
            }
        }

        Ok(())
    }
}

impl<R: AsyncRead + Unpin> Archive<R> {
    /// Securely extracts this archive beneath `dest` under `policy`.
    ///
    /// The destination is created when missing. Regular files replace existing
    /// regular files by unlinking and recreating them. On failure,
    /// already-created entries and replaced regular files may remain, as with
    /// conventional streaming tar extractors. The caller must not concurrently
    /// mutate `dest` while extraction is in progress.
    pub async fn extract<P: AsRef<Path>>(
        mut self,
        dest: P,
        policy: DecodePolicy,
    ) -> Result<(), DecodeError> {
        let mut root = ExtractionRoot::open(dest.as_ref()).await?;
        let mut payload_chunk = Vec::new();
        while let Some(frame) = self.reader.next_frame().await? {
            match frame {
                LogicalFrame::GlobalPax(header) => {
                    policy
                        .pax_policy
                        .check_global_pax_extension(header.position)?;
                    policy.pax_policy.check_pax_records(
                        header.position,
                        PaxKind::Global,
                        &header.records,
                    )?;
                }
                LogicalFrame::Member(mut frame) => {
                    policy.check_format(
                        member_format_position(&frame.header, &frame.extensions),
                        frame.header.format,
                    )?;
                    policy.check_member_kind(frame.header.position, frame.header.kind)?;
                    if let MemberExtensions::Pax {
                        local: Some(local), ..
                    } = &frame.extensions
                    {
                        policy.pax_policy.check_pax_records(
                            local.position,
                            PaxKind::Local,
                            &local.records,
                        )?;
                    }
                    let member = decode_member(&frame)?;
                    if is_buffered_regular_member(&member) {
                        root.prepare_file_path(&member.path).await?;
                        payload_chunk.clear();
                        if member.payload_size != 0
                            && !frame
                                .payload
                                .next_chunk(&mut payload_chunk, EXTRACTION_CHUNK_BYTES)
                                .await?
                        {
                            return Err(DecodeError::InvalidFrameSequence {
                                reason: "buffered member payload ended before its decoded size",
                            });
                        }
                        let buffer = mem::take(&mut payload_chunk);
                        let (returned_buffer, result) =
                            root.create_buffered_file(member, buffer).await;
                        payload_chunk = returned_buffer;
                        result?;
                    } else if let Some(mut writer) = root.start_member(member).await? {
                        while frame
                            .payload
                            .next_chunk(&mut payload_chunk, EXTRACTION_CHUNK_BYTES)
                            .await?
                        {
                            writer.write_chunk(&payload_chunk).await?;
                        }
                    } else {
                        frame.payload.skip().await?;
                    }
                }
            }
        }
        root.install_symlinks(policy.allow_dangling_symlinks).await
    }
}

/// A valid archive feature rejected by the selected [`DecodePolicy`].
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DecodePolicyViolation {
    /// A symbolic-link member appeared when links are forbidden.
    #[error("symbolic-link members are not allowed")]
    SymbolicLink,
    /// A hard-link member appeared when links are forbidden.
    #[error("hard-link members are not allowed")]
    HardLink,
    /// A GNU-family frame appeared when only POSIX-pax extraction is allowed.
    #[error("GNU archives are not allowed")]
    GnuArchive,
    /// A global POSIX pax extended header appeared when it is forbidden.
    #[error("global pax extended headers are not allowed")]
    GlobalPaxExtension,
    /// A vendor-namespaced POSIX pax record appeared.
    #[error("pax vendor extension {vendor}.{name} is not allowed")]
    PaxVendorExtension {
        /// Uppercase vendor namespace.
        vendor: String,
        /// Keyword suffix following the vendor namespace.
        name: String,
    },
    /// One POSIX pax extended header repeats the same logical keyword.
    #[error("pax extended header contains duplicate record {keyword}")]
    DuplicatePaxRecord {
        /// The repeated POSIX pax record keyword.
        keyword: String,
    },
    /// A global POSIX pax header supplies per-member identity or framing data.
    #[error("global pax extended header contains restricted member metadata {keyword}")]
    GlobalPaxMemberMetadata {
        /// The restricted global record keyword.
        keyword: &'static str,
    },
}

/// An error produced while decoding or securely extracting an archive.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// The underlying tar stream is not structurally valid.
    #[error(transparent)]
    Framing(#[from] FrameError),
    /// A destination filesystem operation failed.
    #[error("failed to {operation} {path}: {source}")]
    Filesystem {
        /// The operation that failed.
        operation: &'static str,
        /// The path involved in the failed operation.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// A blocking capability operation failed to complete.
    #[error("failed to complete blocking extraction operation: {0}")]
    BlockingTask(#[from] tokio::task::JoinError),
    /// An effective member path or link target is not UTF-8 text.
    #[error("at byte {position}: {field} is not valid UTF-8")]
    InvalidUtf8 {
        /// Source tar block position.
        position: u64,
        /// Metadata field being decoded.
        field: &'static str,
    },
    /// An archive member path or link value is unsafe to extract.
    #[error("at byte {position}: unsafe {context} {value:?}: {reason}")]
    UnsafePath {
        /// Source member-header position.
        position: u64,
        /// Whether this is a member path or link target.
        context: &'static str,
        /// Archive-provided value.
        value: String,
        /// Rejection reason.
        reason: &'static str,
    },
    /// An archive entry collides with another entry or existing destination path.
    #[error("archive entry collides with existing path {path}")]
    PathCollision {
        /// Normalized extraction-relative path.
        path: PathBuf,
    },
    /// A member kind is deliberately excluded from secure extraction.
    #[error("at byte {position}: cannot extract unsupported member type {kind:?} at {path}")]
    UnsupportedMember {
        /// Source member-header position.
        position: u64,
        /// Normalized extraction-relative path.
        path: PathBuf,
        /// Unsupported member kind.
        kind: MemberKind,
    },
    /// A symbolic or hard link cannot be safely resolved.
    #[error("at byte {position}: invalid link {path} -> {target:?}: {reason}")]
    InvalidLink {
        /// Source member-header position.
        position: u64,
        /// Normalized link path.
        path: PathBuf,
        /// Archive-provided or normalized link target.
        target: String,
        /// Rejection reason.
        reason: &'static str,
    },
    /// A frame stream violated the contract expected from `tar-framing`.
    #[error("invalid tar frame sequence: {reason}")]
    InvalidFrameSequence {
        /// Internal sequence expectation.
        reason: &'static str,
    },
    /// A structurally valid archive feature was rejected by extraction policy.
    #[error("at byte {position}: extraction policy rejected input: {violation}")]
    PolicyViolation {
        /// Source header position for the rejected feature.
        position: u64,
        /// The selected policy rule that rejected the feature.
        violation: DecodePolicyViolation,
    },
}

fn policy_violation(position: u64, violation: DecodePolicyViolation) -> DecodeError {
    DecodeError::PolicyViolation {
        position,
        violation,
    }
}

#[derive(Debug)]
struct DecodedMember {
    position: u64,
    path: PathBuf,
    kind: MemberKind,
    link_target: Option<String>,
    executable: bool,
    payload_size: u64,
}

fn member_format_position(header: &MemberHeader, extensions: &MemberExtensions) -> u64 {
    match extensions {
        MemberExtensions::Pax { .. } => header.position,
        MemberExtensions::Gnu {
            long_name,
            long_link,
        } => long_name
            .iter()
            .chain(long_link.iter())
            .map(|header| header.position)
            .min()
            .unwrap_or(header.position),
    }
}

fn decode_member<R>(frame: &MemberFrame<'_, R>) -> Result<DecodedMember, DecodeError> {
    let header = &frame.header;
    let mode = header.mode()?;
    let executable = mode & 0o111 != 0;
    let path = resolved_text(header.position, "path", frame.effective_path()?)?;
    let link_target = if matches!(header.kind, MemberKind::HardLink | MemberKind::SymbolicLink) {
        Some(resolved_text(
            header.position,
            "linkpath",
            frame.effective_link_path()?,
        )?)
    } else {
        None
    };

    Ok(DecodedMember {
        position: header.position,
        path: normalize_member_path(header.position, &path)?,
        kind: header.kind,
        link_target,
        executable,
        payload_size: header.payload_size,
    })
}

fn is_buffered_regular_member(member: &DecodedMember) -> bool {
    matches!(member.kind, MemberKind::Regular | MemberKind::Contiguous)
        && member.payload_size <= EXTRACTION_CHUNK_BYTES as u64
}

fn resolved_text(
    position: u64,
    keyword: &'static str,
    value: Cow<'_, [u8]>,
) -> Result<String, DecodeError> {
    std::str::from_utf8(value.as_ref())
        .map(str::to_owned)
        .map_err(|_| DecodeError::InvalidUtf8 {
            position,
            field: keyword,
        })
}

fn normalize_member_path(position: u64, value: &str) -> Result<PathBuf, DecodeError> {
    normalize_path(position, "member path", value, &[])
}

fn normalize_hard_link_target(position: u64, value: &str) -> Result<PathBuf, DecodeError> {
    normalize_path(position, "hard-link target", value, &[])
}

fn normalize_symlink_target(
    position: u64,
    path: &Path,
    value: &str,
) -> Result<PathBuf, DecodeError> {
    let base = path.parent().map(path_components).unwrap_or_default();
    normalize_path(position, "symbolic-link target", value, &base)
}

fn normalize_path(
    position: u64,
    context: &'static str,
    value: &str,
    base: &[String],
) -> Result<PathBuf, DecodeError> {
    if value.contains('\0') {
        return unsafe_path(position, context, value, "contains a NUL byte");
    }
    if value.contains('\\') {
        return unsafe_path(position, context, value, "contains a backslash separator");
    }
    if value.starts_with('/') {
        return unsafe_path(position, context, value, "is absolute");
    }
    let mut components = base.to_vec();
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return unsafe_path(position, context, value, "escapes the destination root");
                }
            }
            component if has_windows_prefix(component) => {
                return unsafe_path(position, context, value, "contains a platform path prefix");
            }
            component => components.push(component.to_owned()),
        }
    }
    Ok(components.iter().collect())
}

fn has_windows_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn unsafe_path<T>(
    position: u64,
    context: &'static str,
    value: &str,
    reason: &'static str,
) -> Result<T, DecodeError> {
    Err(DecodeError::UnsafePath {
        position,
        context,
        value: value.to_owned(),
        reason,
    })
}

fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(component) => Some(component.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

#[derive(Clone, Debug)]
struct PendingSymlink {
    position: u64,
    target_text: String,
    target: PathBuf,
    contents: PathBuf,
}

// Keep graph validation bounded when each symbolic-link substitution grows the
// remaining path instead of revisiting an identical expansion.
const MAX_SYMLINK_EXPANSIONS: usize = 256;

struct ExtractionRoot {
    dir: Arc<Dir>,
    extracted_files: HashSet<PathBuf>,
    extracted_directories: HashSet<PathBuf>,
    verified_directories: HashSet<PathBuf>,
    pending_symlinks: HashMap<PathBuf, PendingSymlink>,
    symlink_paths: Vec<PathBuf>,
}

impl ExtractionRoot {
    async fn open(dest: &Path) -> Result<Self, DecodeError> {
        let dest = dest.to_owned();
        let path = dest.clone();
        let dir = tokio::task::spawn_blocking(move || {
            match std::fs::symlink_metadata(&dest) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(io::Error::other(
                        "destination exists but is not a real directory",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std::fs::create_dir_all(&dest)?;
                }
                Err(error) => return Err(error),
            }
            Dir::open_ambient_dir(dest, ambient_authority())
        })
        .await?
        .map_err(|source| filesystem("open destination directory", path, source))?;
        Ok(Self {
            dir: Arc::new(dir),
            extracted_files: HashSet::new(),
            extracted_directories: HashSet::new(),
            verified_directories: HashSet::new(),
            pending_symlinks: HashMap::new(),
            symlink_paths: Vec::new(),
        })
    }

    async fn start_member(
        &mut self,
        member: DecodedMember,
    ) -> Result<Option<ActiveWriter>, DecodeError> {
        if member.path.as_os_str().is_empty() {
            return if member.kind == MemberKind::Directory {
                Ok(None)
            } else {
                unsafe_path(
                    member.position,
                    "member path",
                    ".",
                    "only a directory may name the extraction root",
                )
            };
        }
        match member.kind {
            MemberKind::Regular | MemberKind::Contiguous => self.create_file(member).await,
            MemberKind::Directory => {
                self.create_directory(member).await?;
                Ok(None)
            }
            MemberKind::SymbolicLink => {
                self.reserve_symlink(member).await?;
                Ok(None)
            }
            MemberKind::HardLink => self.create_hard_link(member).await,
            MemberKind::CharacterDevice | MemberKind::BlockDevice | MemberKind::Fifo => {
                Err(DecodeError::UnsupportedMember {
                    position: member.position,
                    path: member.path,
                    kind: member.kind,
                })
            }
        }
    }

    async fn create_file(
        &mut self,
        member: DecodedMember,
    ) -> Result<Option<ActiveWriter>, DecodeError> {
        let std_file = self
            .create_or_replace_file(&member.path, member.executable)
            .await?;
        self.extracted_files.insert(member.path.clone());
        Ok(active_writer(member, std_file))
    }

    async fn create_buffered_file(
        &mut self,
        member: DecodedMember,
        buffer: Vec<u8>,
    ) -> (Vec<u8>, Result<(), DecodeError>) {
        let payload_size = match u64::try_from(buffer.len()) {
            Ok(payload_size) => payload_size,
            Err(_) => {
                return (
                    buffer,
                    Err(DecodeError::InvalidFrameSequence {
                        reason: "buffered payload length cannot be represented",
                    }),
                );
            }
        };
        if payload_size != member.payload_size {
            return (
                buffer,
                Err(DecodeError::InvalidFrameSequence {
                    reason: "buffered payload length did not match the decoded member size",
                }),
            );
        }
        let (buffer, result) = self
            .create_or_replace_buffered_file(&member.path, member.executable, buffer)
            .await;
        if result.is_ok() {
            self.extracted_files.insert(member.path);
        }
        (buffer, result)
    }

    async fn create_directory(&mut self, member: DecodedMember) -> Result<(), DecodeError> {
        self.ensure_parents(&member.path).await?;
        if self.pending_symlinks.contains_key(&member.path) {
            return Err(DecodeError::PathCollision { path: member.path });
        }
        if !self.verified_directories.contains(&member.path) {
            match self.symlink_metadata(&member.path).await? {
                Some(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Some(_) => return Err(DecodeError::PathCollision { path: member.path }),
                None => self.create_dir(&member.path).await?,
            }
            self.verified_directories.insert(member.path.clone());
        }
        self.extracted_directories.insert(member.path);
        Ok(())
    }

    async fn reserve_symlink(&mut self, member: DecodedMember) -> Result<(), DecodeError> {
        let target_text = required_link_target(&member)?;
        let target = normalize_symlink_target(member.position, &member.path, &target_text)?;
        self.ensure_new_path(&member.path).await?;
        let contents = relative_link_contents(&member.path, &target);
        self.pending_symlinks.insert(
            member.path.clone(),
            PendingSymlink {
                position: member.position,
                target_text,
                target,
                contents,
            },
        );
        self.symlink_paths.push(member.path);
        Ok(())
    }

    async fn create_hard_link(
        &mut self,
        member: DecodedMember,
    ) -> Result<Option<ActiveWriter>, DecodeError> {
        let target_text = required_link_target(&member)?;
        let target = normalize_hard_link_target(member.position, &target_text)?;
        if !self.extracted_files.contains(&target) {
            return Err(DecodeError::InvalidLink {
                position: member.position,
                path: member.path,
                target: target_text,
                reason: "hard-link target is not a previously extracted file",
            });
        }
        self.ensure_new_path(&member.path).await?;
        self.hard_link(&target, &member.path).await?;
        self.extracted_files.insert(member.path.clone());
        if member.payload_size == 0 {
            return Ok(None);
        }
        let std_file = self.truncate_file(&member.path).await?;
        Ok(active_writer(member, std_file))
    }

    async fn install_symlinks(&self, allow_dangling_symlinks: bool) -> Result<(), DecodeError> {
        let mut terminal_kinds = Vec::with_capacity(self.symlink_paths.len());
        for path in &self.symlink_paths {
            let link = self.pending_symlinks.get(path).expect("tracked symlink");
            let kind =
                self.resolve_terminal(&link.target)
                    .map_err(|reason| DecodeError::InvalidLink {
                        position: link.position,
                        path: path.clone(),
                        target: link.target_text.clone(),
                        reason,
                    })?;
            if kind == TerminalKind::Dangling && !allow_dangling_symlinks {
                return Err(DecodeError::InvalidLink {
                    position: link.position,
                    path: path.clone(),
                    target: link.target_text.clone(),
                    reason: "target was not created by this extraction",
                });
            }
            terminal_kinds.push((path.clone(), link.clone(), kind));
        }

        for (path, link, kind) in terminal_kinds {
            self.install_symlink(&path, &link.contents, kind).await?;
        }
        Ok(())
    }

    fn resolve_terminal(&self, path: &Path) -> Result<TerminalKind, &'static str> {
        let mut path = path.to_owned();
        let mut visited = HashSet::new();
        let mut expansions = 0;
        loop {
            if !visited.insert(path.clone()) {
                return Err("symbolic-link target cycle");
            }
            let components: Vec<_> = path.components().collect();
            let mut prefix = PathBuf::new();
            let mut rewritten = None;
            for (index, component) in components.iter().enumerate() {
                prefix.push(component.as_os_str());
                if let Some(link) = self.pending_symlinks.get(&prefix) {
                    let mut target = link.target.clone();
                    for remainder in components.iter().skip(index + 1) {
                        target.push(remainder.as_os_str());
                    }
                    rewritten = Some(target);
                    break;
                }
            }
            if let Some(rewritten) = rewritten {
                if expansions == MAX_SYMLINK_EXPANSIONS {
                    return Err("symbolic-link target expansion limit exceeded");
                }
                expansions += 1;
                path = rewritten;
            } else if path.as_os_str().is_empty() || self.extracted_directories.contains(&path) {
                return Ok(TerminalKind::Directory);
            } else if self.extracted_files.contains(&path) {
                return Ok(TerminalKind::File);
            } else {
                return Ok(TerminalKind::Dangling);
            }
        }
    }

    async fn create_or_replace_file(
        &mut self,
        path: &Path,
        executable: bool,
    ) -> Result<std::fs::File, DecodeError> {
        self.prepare_file_path(path).await?;
        let relative = path.to_owned();
        let error_path = relative.clone();
        let dir = Arc::clone(&self.dir);
        tokio::task::spawn_blocking(move || open_or_replace_file(&dir, &relative, executable))
            .await?
            .map(cap_std::fs::File::into_std)
            .map_err(|error| map_file_operation_error(error_path, error))
    }

    async fn create_or_replace_buffered_file(
        &self,
        path: &Path,
        executable: bool,
        buffer: Vec<u8>,
    ) -> (Vec<u8>, Result<(), DecodeError>) {
        let relative = path.to_owned();
        let error_path = relative.clone();
        let dir = Arc::clone(&self.dir);
        with_reusable_buffer(buffer, move |buffer| {
            let result = open_or_replace_file(&dir, &relative, executable).and_then(|mut file| {
                file.write_all(buffer)
                    .map_err(|source| file_operation_error("write file", source))
            });
            buffer.clear();
            result.map_err(|error| map_file_operation_error(error_path, error))
        })
        .await
    }

    async fn prepare_file_path(&mut self, path: &Path) -> Result<(), DecodeError> {
        self.ensure_parents(path).await?;
        if self.pending_symlinks.contains_key(path) {
            return Err(DecodeError::PathCollision {
                path: path.to_owned(),
            });
        }
        Ok(())
    }

    async fn ensure_new_path(&mut self, path: &Path) -> Result<(), DecodeError> {
        self.ensure_parents(path).await?;
        if self.pending_symlinks.contains_key(path) {
            return Err(DecodeError::PathCollision {
                path: path.to_owned(),
            });
        }
        self.reject_existing(path).await
    }

    async fn ensure_parents(&mut self, path: &Path) -> Result<(), DecodeError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        let mut current = PathBuf::new();
        for component in parent.components() {
            current.push(component.as_os_str());
            if self.pending_symlinks.contains_key(&current) {
                return Err(DecodeError::PathCollision {
                    path: current.clone(),
                });
            }
            if self.verified_directories.contains(&current) {
                continue;
            }
            match self.symlink_metadata(&current).await? {
                Some(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    self.verified_directories.insert(current.clone());
                }
                Some(_) => {
                    return Err(DecodeError::PathCollision {
                        path: current.clone(),
                    });
                }
                None => {
                    self.create_dir(&current).await?;
                    self.extracted_directories.insert(current.clone());
                    self.verified_directories.insert(current.clone());
                }
            }
        }
        Ok(())
    }

    async fn reject_existing(&self, path: &Path) -> Result<(), DecodeError> {
        if self.symlink_metadata(path).await?.is_some() {
            Err(DecodeError::PathCollision {
                path: path.to_owned(),
            })
        } else {
            Ok(())
        }
    }

    async fn symlink_metadata(
        &self,
        path: &Path,
    ) -> Result<Option<cap_std::fs::Metadata>, DecodeError> {
        let relative = path.to_owned();
        let error_path = relative.clone();
        let dir = Arc::clone(&self.dir);
        match tokio::task::spawn_blocking(move || dir.symlink_metadata(relative)).await? {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(filesystem("inspect", error_path, source)),
        }
    }

    async fn create_dir(&self, path: &Path) -> Result<(), DecodeError> {
        let relative = path.to_owned();
        let error_path = relative.clone();
        let dir = Arc::clone(&self.dir);
        tokio::task::spawn_blocking(move || dir.create_dir(relative))
            .await?
            .map_err(|source| filesystem("create directory", error_path, source))
    }

    async fn truncate_file(&self, path: &Path) -> Result<std::fs::File, DecodeError> {
        let relative = path.to_owned();
        let error_path = relative.clone();
        let dir = Arc::clone(&self.dir);
        tokio::task::spawn_blocking(move || {
            let mut options = OpenOptions::new();
            options.write(true).truncate(true);
            dir.open_with(relative, &options)
                .map(cap_std::fs::File::into_std)
        })
        .await?
        .map_err(|source| filesystem("truncate file", error_path, source))
    }

    async fn hard_link(&self, target: &Path, path: &Path) -> Result<(), DecodeError> {
        let target = target.to_owned();
        let path = path.to_owned();
        let error_path = path.clone();
        let dir = Arc::clone(&self.dir);
        tokio::task::spawn_blocking(move || dir.hard_link(target, &dir, path))
            .await?
            .map_err(|source| filesystem("create hard link", error_path, source))
    }

    async fn install_symlink(
        &self,
        path: &Path,
        contents: &Path,
        kind: TerminalKind,
    ) -> Result<(), DecodeError> {
        let path = path.to_owned();
        let error_path = path.clone();
        let contents = contents.to_owned();
        let dir = Arc::clone(&self.dir);
        tokio::task::spawn_blocking(move || create_symlink(&dir, &contents, &path, kind))
            .await?
            .map_err(|source| filesystem("create symbolic link", error_path, source))
    }
}

enum FileOperationError {
    Collision,
    Filesystem {
        operation: &'static str,
        source: io::Error,
    },
}

fn open_or_replace_file(
    dir: &Dir,
    path: &Path,
    executable: bool,
) -> Result<cap_std::fs::File, FileOperationError> {
    let file = match create_new_file(dir, path) {
        Ok(file) => file,
        Err(create_error) => {
            // Windows may report an existing directory as permission denied.
            match dir.symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() => {
                    dir.remove_file(path)
                        .map_err(|source| file_operation_error("remove file", source))?;
                    create_new_file(dir, path)
                        .map_err(|source| file_operation_error("create file", source))
                }
                Ok(_) => Err(FileOperationError::Collision),
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    Err(file_operation_error("create file", create_error))
                }
                Err(source) => Err(file_operation_error("inspect", source)),
            }
        }?,
    };
    add_executable(&file, executable)
        .map_err(|source| file_operation_error("create file", source))?;
    Ok(file)
}

fn create_new_file(dir: &Dir, path: &Path) -> io::Result<cap_std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    dir.open_with(path, &options)
}

fn file_operation_error(operation: &'static str, source: io::Error) -> FileOperationError {
    FileOperationError::Filesystem { operation, source }
}

fn map_file_operation_error(path: PathBuf, error: FileOperationError) -> DecodeError {
    match error {
        FileOperationError::Collision => DecodeError::PathCollision { path },
        FileOperationError::Filesystem { operation, source } => filesystem(operation, path, source),
    }
}

fn required_link_target(member: &DecodedMember) -> Result<String, DecodeError> {
    match member.link_target.clone() {
        Some(target) if !target.is_empty() => Ok(target),
        _ => Err(DecodeError::InvalidLink {
            position: member.position,
            path: member.path.clone(),
            target: String::new(),
            reason: "link target is empty",
        }),
    }
}

fn filesystem(operation: &'static str, path: PathBuf, source: io::Error) -> DecodeError {
    DecodeError::Filesystem {
        operation,
        path,
        source,
    }
}

struct ActiveWriter {
    path: PathBuf,
    remaining: u64,
    file: tokio::fs::File,
}

impl ActiveWriter {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), DecodeError> {
        let len = u64::try_from(chunk.len()).map_err(|_| DecodeError::InvalidFrameSequence {
            reason: "payload chunk length cannot be represented",
        })?;
        if len > self.remaining {
            return Err(DecodeError::InvalidFrameSequence {
                reason: "member payload exceeded the decoded member size",
            });
        }
        self.file
            .write_all(chunk)
            .await
            .map_err(|source| filesystem("write file", self.path.clone(), source))?;
        self.remaining -= len;
        if self.remaining == 0 {
            self.file
                .flush()
                .await
                .map_err(|source| filesystem("flush file", self.path.clone(), source))?;
        }
        Ok(())
    }
}

fn active_writer(member: DecodedMember, file: std::fs::File) -> Option<ActiveWriter> {
    (member.payload_size != 0).then(|| ActiveWriter {
        path: member.path,
        remaining: member.payload_size,
        file: tokio::fs::File::from_std(file),
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TerminalKind {
    File,
    Directory,
    Dangling,
}

fn relative_link_contents(link: &Path, target: &Path) -> PathBuf {
    let from = link.parent().map(path_components).unwrap_or_default();
    let to = path_components(target);
    let common = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count();
    let mut contents = PathBuf::new();
    for _ in common..from.len() {
        contents.push("..");
    }
    for component in to.iter().skip(common) {
        contents.push(component);
    }
    if contents.as_os_str().is_empty() {
        contents.push(".");
    }
    contents
}

#[cfg(unix)]
fn add_executable(file: &cap_std::fs::File, executable: bool) -> io::Result<()> {
    use cap_std::fs::PermissionsExt;

    if executable {
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(permissions.mode() | 0o111);
        file.set_permissions(permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn add_executable(_file: &cap_std::fs::File, _executable: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn create_symlink(dir: &Dir, contents: &Path, path: &Path, _kind: TerminalKind) -> io::Result<()> {
    dir.symlink(contents, path)
}

#[cfg(windows)]
fn create_symlink(dir: &Dir, contents: &Path, path: &Path, kind: TerminalKind) -> io::Result<()> {
    match kind {
        TerminalKind::File => dir.symlink_file(contents, path),
        TerminalKind::Directory => dir.symlink_dir(contents, path),
        TerminalKind::Dangling => dir.symlink_file(contents, path),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;
    use tar_framing::{BLOCK_SIZE, Block, FrameErrorInner};
    use tempfile::tempdir;
    use tokio::io::ReadBuf;

    const NAME_RANGE: std::ops::Range<usize> = 0..100;
    const MODE_RANGE: std::ops::Range<usize> = 100..108;
    const LINK_NAME_RANGE: std::ops::Range<usize> = 157..257;
    const SIZE_RANGE: std::ops::Range<usize> = 124..136;
    const CHECKSUM_RANGE: std::ops::Range<usize> = 148..156;
    const TYPEFLAG_OFFSET: usize = 156;
    const IDENTITY_RANGE: std::ops::Range<usize> = 257..265;
    const POSIX_IDENTITY: &[u8; 8] = b"ustar\x0000";
    const GNU_IDENTITY: &[u8; 8] = b"ustar  \0";

    struct ChunkedReader {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl ChunkedReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, offset: 0 }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset == self.bytes.len() {
                return Poll::Ready(Ok(()));
            }
            let len = buffer
                .remaining()
                .min(23)
                .min(self.bytes.len() - self.offset);
            let end = self.offset + len;
            buffer.put_slice(&self.bytes[self.offset..end]);
            self.offset = end;
            Poll::Ready(Ok(()))
        }
    }

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
        let suffix = format!(" {keyword}={value}\n");
        let mut len = suffix.len() + 1;
        loop {
            let value = format!("{len}{suffix}");
            if value.len() == len {
                return value.into_bytes();
            }
            len = value.len();
        }
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
        for chunk in payload.chunks(BLOCK_SIZE) {
            let mut block = [0; BLOCK_SIZE];
            block[..chunk.len()].copy_from_slice(chunk);
            append_block(bytes, &block);
        }
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
        append_block(bytes, &[0; BLOCK_SIZE]);
        append_block(bytes, &[0; BLOCK_SIZE]);
    }

    async fn extract(bytes: Vec<u8>, dest: &Path) -> Result<(), DecodeError> {
        extract_with_policy(bytes, dest, DecodePolicy::default()).await
    }

    async fn extract_with_policy(
        bytes: Vec<u8>,
        dest: &Path,
        policy: DecodePolicy,
    ) -> Result<(), DecodeError> {
        Archive::new(ChunkedReader::new(bytes))
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
    async fn extracts_chunked_multiblock_payload_with_partial_final_block() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let payload = (0..16 * 1024 + BLOCK_SIZE + 7)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "file", b'0', &payload, "", 0o644);
        finish(&mut bytes);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("file")).unwrap(), payload);
    }

    #[tokio::test]
    async fn extracts_streamed_payload_larger_than_the_buffered_threshold() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let payload = (0..EXTRACTION_CHUNK_BYTES + 7)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "file", b'0', &payload, "", 0o644);
        finish(&mut bytes);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("file")).unwrap(), payload);
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

    #[test]
    fn rejects_windows_drive_prefixes_during_path_normalization() {
        assert_eq!(
            normalize_member_path(0, "tests/snippets/ballon:main.py").unwrap(),
            PathBuf::from("tests/snippets/ballon:main.py")
        );
        for value in ["C:", "C:/escape", "nested/C:/escape"] {
            assert!(matches!(
                normalize_member_path(0, value),
                Err(DecodeError::UnsafePath {
                    reason: "contains a platform path prefix",
                    ..
                })
            ));
        }
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
    async fn applies_gnu_long_name_and_long_link_metadata() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_gnu_member(&mut bytes, "dir/target", b'0', b"target", "", 0o644);
        append_gnu_member(&mut bytes, "longname", b'L', b"dir/long/link\0", "", 0o644);
        append_gnu_member(&mut bytes, "longlink", b'K', b"../target\0", "", 0o644);
        append_gnu_member(&mut bytes, "raw", b'2', b"", "wrong", 0o644);
        finish(&mut bytes);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("dir/long/link")).unwrap(),
            "target"
        );
    }

    #[tokio::test]
    async fn applies_multiblock_gnu_long_name_and_long_link_metadata() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let prefix = "./".repeat(BLOCK_SIZE);
        let mut long_name = format!("{prefix}alias").into_bytes();
        long_name.push(0);
        let mut long_link = format!("{prefix}target").into_bytes();
        long_link.push(0);

        let mut bytes = Vec::new();
        append_gnu_member(&mut bytes, "target", b'0', b"contents", "", 0o644);
        append_gnu_member(&mut bytes, "longname", b'L', &long_name, "", 0o644);
        append_gnu_member(&mut bytes, "longlink", b'K', &long_link, "", 0o644);
        append_gnu_member(&mut bytes, "raw", b'2', b"", "wrong", 0o644);
        finish(&mut bytes);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("alias")).unwrap(),
            "contents"
        );
    }

    #[tokio::test]
    async fn rejects_unsafe_paths_cross_kind_collisions_and_unsupported_members() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir(dest.join("occupied")).unwrap();

        for (name, kind, expected) in [
            ("../escape", b'0', "unsafe"),
            ("occupied", b'0', "collision"),
            ("device", b'3', "unsupported"),
        ] {
            let mut bytes = Vec::new();
            append_posix_member(&mut bytes, name, kind, b"", "", 0o644);
            finish(&mut bytes);
            let error = extract(bytes, &dest).await.unwrap_err();
            match expected {
                "unsafe" => assert!(matches!(error, DecodeError::UnsafePath { .. })),
                "collision" => assert!(matches!(error, DecodeError::PathCollision { .. })),
                "unsupported" => assert!(matches!(error, DecodeError::UnsupportedMember { .. })),
                _ => unreachable!(),
            }
        }
        assert!(dest.join("occupied").is_dir());
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
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "same", b'0', b"archive", "", 0o644);
        finish(&mut bytes);

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
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "same", b'0', b"archive", "", 0o755);
        finish(&mut bytes);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read(dest.join("same")).unwrap(), b"archive");
        assert_eq!(std::fs::read(dest.join("sibling")).unwrap(), b"ambient");
        let replaced = std::fs::metadata(dest.join("same")).unwrap();
        let sibling = std::fs::metadata(dest.join("sibling")).unwrap();
        assert_ne!(replaced.ino(), sibling.ino());
        assert_ne!(replaced.permissions().mode() & 0o111, 0);
    }

    #[tokio::test]
    async fn rejects_cross_kind_conflicts_and_reuses_real_directories() {
        let temp = tempdir().unwrap();

        let directory_dest = temp.path().join("directory");
        let mut directory = Vec::new();
        append_posix_member(&mut directory, "same", b'5', b"", "", 0o755);
        append_posix_member(&mut directory, "same", b'0', b"file", "", 0o644);
        finish(&mut directory);
        assert!(matches!(
            extract(directory, &directory_dest).await.unwrap_err(),
            DecodeError::PathCollision { .. }
        ));
        assert!(directory_dest.join("same").is_dir());

        let repeated_directory_dest = temp.path().join("repeated-directory");
        let mut repeated_directory = Vec::new();
        append_posix_member(&mut repeated_directory, "same", b'5', b"", "", 0o755);
        append_posix_member(&mut repeated_directory, "same", b'5', b"", "", 0o755);
        finish(&mut repeated_directory);
        extract(repeated_directory, &repeated_directory_dest)
            .await
            .unwrap();
        assert!(repeated_directory_dest.join("same").is_dir());

        let ambient_directory_dest = temp.path().join("ambient-directory");
        std::fs::create_dir_all(ambient_directory_dest.join("same")).unwrap();
        let mut ambient_directory = Vec::new();
        append_posix_member(&mut ambient_directory, "same", b'5', b"", "", 0o755);
        finish(&mut ambient_directory);
        extract(ambient_directory, &ambient_directory_dest)
            .await
            .unwrap();
        assert!(ambient_directory_dest.join("same").is_dir());

        let symbolic_link_dest = temp.path().join("symbolic-link");
        let mut symbolic_link = Vec::new();
        append_posix_member(&mut symbolic_link, "same", b'2', b"", "missing", 0o644);
        append_posix_member(&mut symbolic_link, "same", b'0', b"file", "", 0o644);
        finish(&mut symbolic_link);
        assert!(matches!(
            extract(symbolic_link, &symbolic_link_dest)
                .await
                .unwrap_err(),
            DecodeError::PathCollision { .. }
        ));
        assert!(!symbolic_link_dest.join("same").exists());

        let symbolic_link_parent_dest = temp.path().join("symbolic-link-parent");
        let mut symbolic_link_parent = Vec::new();
        append_posix_member(
            &mut symbolic_link_parent,
            "parent",
            b'2',
            b"",
            "missing",
            0o644,
        );
        append_posix_member(
            &mut symbolic_link_parent,
            "parent/file",
            b'0',
            b"file",
            "",
            0o644,
        );
        finish(&mut symbolic_link_parent);
        assert!(matches!(
            extract(symbolic_link_parent, &symbolic_link_parent_dest)
                .await
                .unwrap_err(),
            DecodeError::PathCollision { .. }
        ));
        assert!(!symbolic_link_parent_dest.join("parent").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_preexisting_symlink_parents() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, dest.join("parent")).unwrap();
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "parent/file", b'0', b"bad", "", 0o644);
        finish(&mut bytes);

        assert!(matches!(
            extract(bytes, &dest).await.unwrap_err(),
            DecodeError::PathCollision { .. }
        ));
        assert!(!outside.join("file").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_preexisting_final_symlinks_instead_of_following_them() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&dest).unwrap();
        std::fs::write(&outside, b"keep").unwrap();
        symlink(&outside, dest.join("same")).unwrap();
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "same", b'0', b"bad", "", 0o644);
        finish(&mut bytes);

        assert!(matches!(
            extract(bytes, &dest).await.unwrap_err(),
            DecodeError::PathCollision { .. }
        ));
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
        let mut dangling = Vec::new();
        append_posix_member(&mut dangling, "link", b'2', b"", "missing", 0o644);
        finish(&mut dangling);
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
    async fn strict_dangling_symlinks_reject_missing_targets() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "link", b'2', b"", "missing", 0o644);
        finish(&mut bytes);
        assert!(matches!(
            extract_with_policy(
                bytes,
                &dest,
                DecodePolicy::default().allow_dangling_symlinks(false)
            )
            .await
            .unwrap_err(),
            DecodeError::InvalidLink { .. }
        ));
        assert!(!dest.join("link").exists());
    }

    #[tokio::test]
    async fn strict_dangling_symlinks_allow_the_extraction_root() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "link", b'2', b"", ".", 0o644);
        finish(&mut bytes);
        extract_with_policy(
            bytes,
            &dest,
            DecodePolicy::default().allow_dangling_symlinks(false),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_link(dest.join("link")).unwrap(),
            Path::new(".")
        );
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
        let cycle_dest = temp.path().join("cycle");
        let mut cycle = Vec::new();
        append_posix_member(&mut cycle, "a", b'2', b"", "b", 0o644);
        append_posix_member(&mut cycle, "b", b'2', b"", "a", 0o644);
        finish(&mut cycle);
        assert!(matches!(
            extract(cycle, &cycle_dest).await.unwrap_err(),
            DecodeError::InvalidLink { .. }
        ));
        assert!(!cycle_dest.join("a").exists());
        assert!(!cycle_dest.join("b").exists());

        let growing_cycle_dest = temp.path().join("growing-cycle");
        let mut growing_cycle = Vec::new();
        append_posix_member(&mut growing_cycle, "a", b'2', b"", "b/x", 0o644);
        append_posix_member(&mut growing_cycle, "b", b'2', b"", "a/y", 0o644);
        finish(&mut growing_cycle);
        assert!(matches!(
            extract(growing_cycle, &growing_cycle_dest)
                .await
                .unwrap_err(),
            DecodeError::InvalidLink {
                reason: "symbolic-link target expansion limit exceeded",
                ..
            }
        ));
        assert!(!growing_cycle_dest.join("a").exists());
        assert!(!growing_cycle_dest.join("b").exists());

        let escape_dest = temp.path().join("escape");
        let mut escape = Vec::new();
        append_posix_member(&mut escape, "link", b'2', b"", "../outside", 0o644);
        finish(&mut escape);
        assert!(matches!(
            extract(escape, &escape_dest).await.unwrap_err(),
            DecodeError::UnsafePath { .. }
        ));
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

        let forward_dest = temp.path().join("forward");
        let mut forward = Vec::new();
        append_posix_member(&mut forward, "b", b'1', b"", "a", 0o644);
        finish(&mut forward);
        assert!(matches!(
            extract_with_policy(forward, &forward_dest, policy)
                .await
                .unwrap_err(),
            DecodeError::InvalidLink { .. }
        ));

        let ambient_dest = temp.path().join("ambient");
        std::fs::create_dir(&ambient_dest).unwrap();
        std::fs::write(ambient_dest.join("a"), b"ambient").unwrap();
        let mut ambient = Vec::new();
        append_posix_member(&mut ambient, "b", b'1', b"", "a", 0o644);
        finish(&mut ambient);
        assert!(matches!(
            extract_with_policy(ambient, &ambient_dest, policy)
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
        let mut hard_link = Vec::new();
        append_posix_member(&mut hard_link, "link", b'1', b"", "missing", 0o644);
        finish(&mut hard_link);
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
        for (case, typeflag, payload, add_member) in [
            ("local", b'x', record("ACME.attribute", "value"), true),
            (
                "active-global",
                b'g',
                record("ACME.attribute", "value"),
                true,
            ),
            ("deleted-global", b'g', record("ACME.attribute", ""), false),
            (
                "replaced-global",
                b'g',
                {
                    let mut payload = record("ACME.attribute", "value");
                    payload.extend_from_slice(&record("ACME.attribute", ""));
                    payload
                },
                false,
            ),
        ] {
            let dest = temp.path().join(case);
            let mut bytes = Vec::new();
            append_pax(&mut bytes, typeflag, &payload);
            if add_member {
                append_posix_member(&mut bytes, "file", b'0', b"", "", 0o644);
            }
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

        let rejected_dest = temp.path().join("rejected");
        let mut rejected = Vec::new();
        append_pax(&mut rejected, b'x', &local);
        append_posix_member(&mut rejected, "raw", b'0', b"contents", "", 0o644);
        finish(&mut rejected);
        assert!(matches!(
            extract(rejected, &rejected_dest).await.unwrap_err(),
            DecodeError::PolicyViolation {
                position: 0,
                violation: DecodePolicyViolation::DuplicatePaxRecord { keyword },
            } if keyword == "path"
        ));
        assert!(!rejected_dest.join("actual").exists());

        let permitted_dest = temp.path().join("permitted");
        let mut permitted = Vec::new();
        append_pax(&mut permitted, b'x', &local);
        append_posix_member(&mut permitted, "raw", b'0', b"contents", "", 0o644);
        finish(&mut permitted);
        extract_with_policy(
            permitted,
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
    async fn rejects_member_specific_global_pax_records_when_global_extensions_are_allowed() {
        let temp = tempdir().unwrap();
        for (keyword, value) in [("path", "file"), ("linkpath", "target"), ("size", "0")] {
            let dest = temp.path().join(keyword);
            let mut bytes = Vec::new();
            append_pax(&mut bytes, b'g', &record(keyword, value));
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

        let deleted_dest = temp.path().join("deleted");
        let mut deleted = Vec::new();
        append_pax(&mut deleted, b'g', &record("path", ""));
        finish(&mut deleted);
        assert!(matches!(
            extract_with_policy(
                deleted,
                &deleted_dest,
                DecodePolicy::default()
                    .pax_policy(PaxDecodePolicy::default().allow_global_pax_extensions(true))
            )
            .await
            .unwrap_err(),
            DecodeError::PolicyViolation {
                position: 0,
                violation: DecodePolicyViolation::GlobalPaxMemberMetadata { keyword: "path" },
            }
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_extension_text_and_preserves_partial_outputs() {
        let temp = tempdir().unwrap();
        let deleted_dest = temp.path().join("deleted");
        let mut deleted = Vec::new();
        append_pax(&mut deleted, b'x', &record("path", ""));
        append_posix_member(&mut deleted, "raw", b'0', b"", "", 0o644);
        finish(&mut deleted);
        assert!(matches!(
            extract(deleted, &deleted_dest).await.unwrap_err(),
            DecodeError::Framing(FrameError {
                inner: FrameErrorInner::DeletedPaxMetadata { keyword: "path" },
                ..
            })
        ));

        let binary_dest = temp.path().join("binary");
        let mut binary_path = record("hdrcharset", "BINARY");
        binary_path.extend_from_slice(&raw_record("path", &[0xff]));
        let mut binary = Vec::new();
        append_pax(&mut binary, b'x', &binary_path);
        append_posix_member(&mut binary, "raw", b'0', b"", "", 0o644);
        finish(&mut binary);
        assert!(matches!(
            extract(binary, &binary_dest).await.unwrap_err(),
            DecodeError::InvalidUtf8 { field: "path", .. }
        ));

        let gnu_dest = temp.path().join("gnu");
        let mut malformed_gnu = Vec::new();
        append_gnu_member(&mut malformed_gnu, "longname", b'L', b"no-nul", "", 0o644);
        append_gnu_member(&mut malformed_gnu, "raw", b'0', b"", "", 0o644);
        finish(&mut malformed_gnu);
        assert!(matches!(
            extract(malformed_gnu, &gnu_dest).await.unwrap_err(),
            DecodeError::Framing(FrameError {
                inner: FrameErrorInner::InvalidGnuMetadata { .. },
                ..
            })
        ));

        let utf8_dest = temp.path().join("utf8");
        let mut invalid_utf8 = header(POSIX_IDENTITY, "name", b'0', 0, "", 0o644);
        invalid_utf8[NAME_RANGE.start] = 0xff;
        set_checksum(&mut invalid_utf8);
        let mut invalid_utf8_archive = invalid_utf8.to_vec();
        finish(&mut invalid_utf8_archive);
        assert!(matches!(
            extract(invalid_utf8_archive, &utf8_dest).await.unwrap_err(),
            DecodeError::InvalidUtf8 { .. }
        ));

        let mode_dest = temp.path().join("mode");
        let mut invalid_mode = header(POSIX_IDENTITY, "mode", b'0', 0, "", 0o644);
        invalid_mode[MODE_RANGE].copy_from_slice(b"0000080\0");
        set_checksum(&mut invalid_mode);
        let mut invalid_mode_archive = invalid_mode.to_vec();
        finish(&mut invalid_mode_archive);
        assert!(matches!(
            extract(invalid_mode_archive, &mode_dest).await.unwrap_err(),
            DecodeError::Framing(FrameError {
                inner: FrameErrorInner::InvalidMode { .. },
                ..
            })
        ));

        let partial_dest = temp.path().join("partial");
        let mut partial = Vec::new();
        append_posix_member(&mut partial, "created", b'0', b"kept", "", 0o644);
        let mut invalid = header(POSIX_IDENTITY, "bad", b'0', 0, "", 0o644);
        invalid[IDENTITY_RANGE.start] = b'!';
        set_checksum(&mut invalid);
        append_block(&mut partial, &invalid);
        assert!(matches!(
            extract(partial, &partial_dest).await.unwrap_err(),
            DecodeError::Framing(_)
        ));
        assert_eq!(
            std::fs::read_to_string(partial_dest.join("created")).unwrap(),
            "kept"
        );
    }
}
