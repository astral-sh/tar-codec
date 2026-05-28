//! Secure high-level extraction for validated tar streams.
//!
//! `tar-codec` interprets member metadata above [`tar_framing`] and extracts
//! archive contents into a capability-scoped destination. Compression is the
//! caller's responsibility. Extraction requires an [`ExtractPolicy`] so that
//! security-sensitive archive features are explicit at each call site.

use std::{
    collections::{HashMap, HashSet},
    io,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use tar_framing::{
    ArchiveFormat, DataFrame, DataOwner, Frame, FrameError, GnuKind, HeaderFrame, MemberKind,
    PaxRecord, PaxValue, TarStream,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio_stream::StreamExt;

const NAME_RANGE: std::ops::Range<usize> = 0..100;
const MODE_RANGE: std::ops::Range<usize> = 100..108;
const LINK_NAME_RANGE: std::ops::Range<usize> = 157..257;
const PREFIX_RANGE: std::ops::Range<usize> = 345..500;

/// A one-pass reader for a validated POSIX-pax or GNU tar archive.
pub struct Archive<R> {
    frames: TarStream<R>,
}

impl<R> Archive<R> {
    /// Creates an archive decoder from an uncompressed tar reader.
    pub fn new(reader: R) -> Self {
        Self {
            frames: TarStream::new(reader),
        }
    }
}

/// Controls which otherwise valid archive features extraction may accept.
///
/// The default permits symbolic links and either supported framing family,
/// while rejecting hard links, vendor-namespaced POSIX pax records, and
/// repeated keywords within one POSIX pax extended header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtractPolicy {
    allow_symlinks: bool,
    allow_hard_links: bool,
    allow_gnu: bool,
    allow_pax_vendor_extensions: bool,
    allow_duplicate_pax_records: bool,
}

impl Default for ExtractPolicy {
    fn default() -> Self {
        Self {
            allow_symlinks: true,
            allow_hard_links: false,
            allow_gnu: true,
            allow_pax_vendor_extensions: false,
            allow_duplicate_pax_records: false,
        }
    }
}

impl ExtractPolicy {
    /// Configures whether symbolic-link members may be extracted.
    pub fn allow_symlinks(mut self, allow: bool) -> Self {
        self.allow_symlinks = allow;
        self
    }

    /// Configures whether hard-link members may be extracted.
    ///
    /// When enabled, POSIX `linkdata` payloads may update the contents of an
    /// earlier extracted file through its shared inode.
    pub fn allow_hard_links(mut self, allow: bool) -> Self {
        self.allow_hard_links = allow;
        self
    }

    /// Configures whether archives in the GNU framing family may be extracted.
    pub fn allow_gnu(mut self, allow: bool) -> Self {
        self.allow_gnu = allow;
        self
    }

    /// Configures whether vendor-namespaced POSIX pax records may be accepted.
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

    fn check_format(&self, position: u64, format: ArchiveFormat) -> Result<(), ExtractError> {
        if format == ArchiveFormat::Gnu && !self.allow_gnu {
            return Err(policy_violation(
                position,
                ExtractPolicyViolation::GnuArchive,
            ));
        }
        Ok(())
    }

    fn check_member_kind(&self, position: u64, kind: MemberKind) -> Result<(), ExtractError> {
        let violation = match kind {
            MemberKind::SymbolicLink if !self.allow_symlinks => {
                Some(ExtractPolicyViolation::SymbolicLink)
            }
            MemberKind::HardLink if !self.allow_hard_links => {
                Some(ExtractPolicyViolation::HardLink)
            }
            _ => None,
        };
        if let Some(violation) = violation {
            return Err(policy_violation(position, violation));
        }
        Ok(())
    }

    fn check_pax_records(&self, position: u64, records: &[PaxRecord]) -> Result<(), ExtractError> {
        if !self.allow_pax_vendor_extensions {
            for record in records {
                if let PaxRecord::Vendor { vendor, name, .. } = record {
                    return Err(policy_violation(
                        position,
                        ExtractPolicyViolation::PaxVendorExtension {
                            vendor: vendor.clone(),
                            name: name.clone(),
                        },
                    ));
                }
            }
        }

        if !self.allow_duplicate_pax_records {
            let mut keywords = HashSet::new();
            for record in records {
                let keyword = pax_record_keyword(record);
                if !keywords.insert(keyword.clone()) {
                    return Err(policy_violation(
                        position,
                        ExtractPolicyViolation::DuplicatePaxRecord { keyword },
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
    /// The destination is created when missing. Existing contents are never
    /// overwritten. On failure, already-created non-symlink entries may
    /// remain, as with conventional streaming tar extractors. The caller must
    /// not concurrently mutate `dest` while extraction is in progress.
    pub async fn extract<P: AsRef<Path>>(
        mut self,
        dest: P,
        policy: ExtractPolicy,
    ) -> Result<(), ExtractError> {
        let mut root = ExtractionRoot::open(dest.as_ref()).await?;
        let mut gnu = GnuMetadata::default();
        let mut active_writer: Option<ActiveWriter> = None;
        let mut pax_position = None;

        while let Some(frame) = self.frames.next().await {
            match frame? {
                Frame::Pax(frame) => {
                    pax_position = Some(frame.position);
                }
                Frame::Gnu(frame) => {
                    policy.check_format(frame.position, ArchiveFormat::Gnu)?;
                    gnu.start(frame.kind);
                }
                Frame::Header(frame) => {
                    if active_writer.is_some() {
                        return Err(ExtractError::InvalidFrameSequence {
                            reason: "received a member header while data was still pending",
                        });
                    }
                    let format =
                        self.frames
                            .format()
                            .ok_or(ExtractError::InvalidFrameSequence {
                                reason: "member header did not identify an archive format",
                            })?;
                    policy.check_format(frame.position, format)?;
                    policy.check_member_kind(frame.position, frame.kind)?;
                    let member = decode_member(format, frame, &mut gnu)?;
                    active_writer = root.start_member(member).await?;
                }
                Frame::Data(frame) => match frame.owner {
                    DataOwner::Pax(_) => {
                        if let Some(records) = frame.completed_pax_records.as_deref() {
                            let position =
                                pax_position
                                    .take()
                                    .ok_or(ExtractError::InvalidFrameSequence {
                                        reason: "pax payload appeared before its header",
                                    })?;
                            policy.check_pax_records(position, records)?;
                        }
                    }
                    DataOwner::Gnu(kind) => gnu.push(kind, &frame.block[..frame.len])?,
                    DataOwner::Member => {
                        let Some(writer) = active_writer.as_mut() else {
                            return Err(ExtractError::InvalidFrameSequence {
                                reason: "received member data without an extracted file",
                            });
                        };
                        if writer.write_frame(frame).await? {
                            active_writer = None;
                        }
                    }
                },
            }
        }

        if active_writer.is_some() {
            return Err(ExtractError::InvalidFrameSequence {
                reason: "member data ended before its output file was complete",
            });
        }
        root.install_symlinks().await
    }
}

/// A valid archive feature rejected by the selected [`ExtractPolicy`].
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ExtractPolicyViolation {
    /// A symbolic-link member appeared when links are forbidden.
    #[error("symbolic-link members are not allowed")]
    SymbolicLink,
    /// A hard-link member appeared when links are forbidden.
    #[error("hard-link members are not allowed")]
    HardLink,
    /// A GNU-family frame appeared when only POSIX-pax extraction is allowed.
    #[error("GNU archives are not allowed")]
    GnuArchive,
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
}

/// An error produced while decoding or securely extracting an archive.
#[derive(Debug, Error)]
pub enum ExtractError {
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
    /// A tar header or GNU metadata value is not UTF-8 text.
    #[error("at byte {position}: {field} is not valid UTF-8")]
    InvalidUtf8 {
        /// Source tar block position.
        position: u64,
        /// Metadata field being decoded.
        field: &'static str,
    },
    /// A GNU long-name or long-link value is malformed.
    #[error("at byte {position}: malformed GNU {field}: {reason}")]
    InvalidGnuMetadata {
        /// Source tar block position.
        position: u64,
        /// GNU metadata field being decoded.
        field: &'static str,
        /// The reason decoding failed.
        reason: &'static str,
    },
    /// A member mode field cannot be decoded.
    #[error("at byte {position}: invalid tar mode field: found {found:?}")]
    InvalidMode {
        /// Source tar block position.
        position: u64,
        /// Raw mode bytes.
        found: [u8; 8],
    },
    /// Required pax metadata was explicitly removed.
    #[error("at byte {position}: pax metadata {keyword:?} is empty for this member")]
    DeletedPaxMetadata {
        /// Source member-header position.
        position: u64,
        /// Metadata keyword.
        keyword: &'static str,
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
    /// A hard link would mutate executable intent on an existing inode.
    #[error("at byte {position}: hard link {path} has executable status different from {target}")]
    HardLinkExecutableMismatch {
        /// Source member-header position.
        position: u64,
        /// New hard-link path.
        path: PathBuf,
        /// Existing linked target.
        target: PathBuf,
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
        violation: ExtractPolicyViolation,
    },
}

fn policy_violation(position: u64, violation: ExtractPolicyViolation) -> ExtractError {
    ExtractError::PolicyViolation {
        position,
        violation,
    }
}

fn pax_record_keyword(record: &PaxRecord) -> String {
    match record {
        PaxRecord::Atime(_) => "atime".to_owned(),
        PaxRecord::Charset(_) => "charset".to_owned(),
        PaxRecord::Comment(_) => "comment".to_owned(),
        PaxRecord::Gid(_) => "gid".to_owned(),
        PaxRecord::Gname(_) => "gname".to_owned(),
        PaxRecord::HdrCharset(_) => "hdrcharset".to_owned(),
        PaxRecord::LinkPath(_) => "linkpath".to_owned(),
        PaxRecord::Mtime(_) => "mtime".to_owned(),
        PaxRecord::Path(_) => "path".to_owned(),
        PaxRecord::Realtime { name, .. } => format!("realtime.{name}"),
        PaxRecord::Security { name, .. } => format!("security.{name}"),
        PaxRecord::Size(_) => "size".to_owned(),
        PaxRecord::Uid(_) => "uid".to_owned(),
        PaxRecord::Uname(_) => "uname".to_owned(),
        PaxRecord::Vendor { vendor, name, .. } => format!("{vendor}.{name}"),
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

#[derive(Default)]
struct GnuMetadata {
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
}

impl GnuMetadata {
    fn start(&mut self, kind: GnuKind) {
        match kind {
            GnuKind::LongName => self.long_name = Some(Vec::new()),
            GnuKind::LongLink => self.long_link = Some(Vec::new()),
        }
    }

    fn push(&mut self, kind: GnuKind, bytes: &[u8]) -> Result<(), ExtractError> {
        let slot = match kind {
            GnuKind::LongName => &mut self.long_name,
            GnuKind::LongLink => &mut self.long_link,
        };
        let Some(payload) = slot.as_mut() else {
            return Err(ExtractError::InvalidFrameSequence {
                reason: "GNU payload appeared before its metadata header",
            });
        };
        payload.extend_from_slice(bytes);
        Ok(())
    }

    fn take_name(&mut self, position: u64) -> Result<Option<String>, ExtractError> {
        self.long_name
            .take()
            .map(|bytes| parse_gnu_text(position, "long-name", &bytes))
            .transpose()
    }

    fn take_link(&mut self, position: u64) -> Result<Option<String>, ExtractError> {
        self.long_link
            .take()
            .map(|bytes| parse_gnu_text(position, "long-link", &bytes))
            .transpose()
    }
}

fn decode_member(
    format: ArchiveFormat,
    header: HeaderFrame,
    gnu: &mut GnuMetadata,
) -> Result<DecodedMember, ExtractError> {
    let mode = parse_mode(header.position, format, &header.block[MODE_RANGE])?;
    let executable = mode & 0o111 != 0;
    let (path, link_target) = match format {
        ArchiveFormat::PosixPax => {
            let raw_path = posix_header_path(header.position, &header.block)?;
            let path = pax_text(&header, PaxTextField::Path)?
                .map(str::to_owned)
                .unwrap_or(raw_path);
            let link_target =
                if matches!(header.kind, MemberKind::HardLink | MemberKind::SymbolicLink) {
                    let raw_link =
                        header_text(header.position, "link name", &header.block[LINK_NAME_RANGE])?;
                    Some(
                        pax_text(&header, PaxTextField::LinkPath)?
                            .map(str::to_owned)
                            .unwrap_or(raw_link),
                    )
                } else {
                    None
                };
            (path, link_target)
        }
        ArchiveFormat::Gnu => {
            let path = gnu.take_name(header.position)?.unwrap_or(header_text(
                header.position,
                "name",
                &header.block[NAME_RANGE],
            )?);
            let link_target =
                if matches!(header.kind, MemberKind::HardLink | MemberKind::SymbolicLink) {
                    Some(gnu.take_link(header.position)?.unwrap_or(header_text(
                        header.position,
                        "link name",
                        &header.block[LINK_NAME_RANGE],
                    )?))
                } else {
                    let _ = gnu.take_link(header.position)?;
                    None
                };
            (path, link_target)
        }
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

#[derive(Clone, Copy)]
enum PaxTextField {
    Path,
    LinkPath,
}

impl PaxTextField {
    fn keyword(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::LinkPath => "linkpath",
        }
    }

    fn value(self, record: &PaxRecord) -> Option<&PaxValue<String>> {
        match (self, record) {
            (Self::Path, PaxRecord::Path(value)) | (Self::LinkPath, PaxRecord::LinkPath(value)) => {
                Some(value)
            }
            _ => None,
        }
    }
}

fn pax_text(header: &HeaderFrame, field: PaxTextField) -> Result<Option<&str>, ExtractError> {
    let value = header
        .local_pax_records
        .iter()
        .rev()
        .find_map(|record| field.value(record))
        .or_else(|| {
            header
                .global_pax_records
                .iter()
                .rev()
                .find_map(|record| field.value(record))
        });
    match value {
        Some(PaxValue::Value(value)) => Ok(Some(value.as_str())),
        Some(PaxValue::Deleted) => Err(ExtractError::DeletedPaxMetadata {
            position: header.position,
            keyword: field.keyword(),
        }),
        None => Ok(None),
    }
}

fn posix_header_path(
    position: u64,
    block: &[u8; tar_framing::BLOCK_SIZE],
) -> Result<String, ExtractError> {
    let name = header_text(position, "name", &block[NAME_RANGE])?;
    let prefix = header_text(position, "prefix", &block[PREFIX_RANGE])?;
    if prefix.is_empty() {
        Ok(name)
    } else if name.is_empty() {
        Ok(prefix)
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn header_text(position: u64, field: &'static str, bytes: &[u8]) -> Result<String, ExtractError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| ExtractError::InvalidUtf8 { position, field })
}

fn parse_gnu_text(
    position: u64,
    field: &'static str,
    bytes: &[u8],
) -> Result<String, ExtractError> {
    let terminator =
        bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ExtractError::InvalidGnuMetadata {
                position,
                field,
                reason: "value is not NUL-terminated",
            })?;
    if bytes[terminator..].iter().any(|byte| *byte != 0) {
        return Err(ExtractError::InvalidGnuMetadata {
            position,
            field,
            reason: "non-NUL bytes follow the terminator",
        });
    }
    std::str::from_utf8(&bytes[..terminator])
        .map(str::to_owned)
        .map_err(|_| ExtractError::InvalidUtf8 { position, field })
}

fn parse_mode(position: u64, format: ArchiveFormat, bytes: &[u8]) -> Result<u64, ExtractError> {
    let found: [u8; 8] = bytes.try_into().expect("fixed mode field range");
    let mode = match format {
        ArchiveFormat::PosixPax => parse_octal(bytes),
        ArchiveFormat::Gnu => parse_gnu_number(bytes),
    };
    mode.ok_or(ExtractError::InvalidMode { position, found })
}

fn parse_octal(bytes: &[u8]) -> Option<u64> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return None;
    }
    let terminator = bytes.iter().position(|byte| matches!(byte, 0 | b' '))?;
    if terminator == 0
        || bytes[..terminator]
            .iter()
            .any(|byte| !matches!(byte, b'0'..=b'7'))
        || bytes[terminator..]
            .iter()
            .any(|byte| !matches!(byte, 0 | b' '))
    {
        return None;
    }
    bytes[..terminator].iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(8)?.checked_add(u64::from(*byte - b'0'))
    })
}

fn parse_gnu_number(bytes: &[u8]) -> Option<u64> {
    if bytes.first() != Some(&0x80) {
        return parse_octal(bytes);
    }
    bytes[1..].iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(256)?.checked_add(u64::from(*byte))
    })
}

fn normalize_member_path(position: u64, value: &str) -> Result<PathBuf, ExtractError> {
    normalize_path(position, "member path", value, &[])
}

fn normalize_hard_link_target(position: u64, value: &str) -> Result<PathBuf, ExtractError> {
    normalize_path(position, "hard-link target", value, &[])
}

fn normalize_symlink_target(
    position: u64,
    path: &Path,
    value: &str,
) -> Result<PathBuf, ExtractError> {
    let base = path.parent().map(path_components).unwrap_or_default();
    normalize_path(position, "symbolic-link target", value, &base)
}

fn normalize_path(
    position: u64,
    context: &'static str,
    value: &str,
    base: &[String],
) -> Result<PathBuf, ExtractError> {
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
            component if component.contains(':') => {
                return unsafe_path(position, context, value, "contains a platform path prefix");
            }
            component => components.push(component.to_owned()),
        }
    }
    Ok(components.iter().collect())
}

fn unsafe_path<T>(
    position: u64,
    context: &'static str,
    value: &str,
    reason: &'static str,
) -> Result<T, ExtractError> {
    Err(ExtractError::UnsafePath {
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
enum EntryKind {
    File { executable: bool },
    Directory { declared: bool },
    SymbolicLink(PendingSymlink),
}

#[derive(Clone, Debug)]
struct PendingSymlink {
    position: u64,
    target_text: String,
    target: PathBuf,
    contents: PathBuf,
}

struct ExtractionRoot {
    dir: Arc<Dir>,
    entries: HashMap<PathBuf, EntryKind>,
    symlinks: Vec<PathBuf>,
}

impl ExtractionRoot {
    async fn open(dest: &Path) -> Result<Self, ExtractError> {
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
            entries: HashMap::new(),
            symlinks: Vec::new(),
        })
    }

    async fn start_member(
        &mut self,
        member: DecodedMember,
    ) -> Result<Option<ActiveWriter>, ExtractError> {
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
                Err(ExtractError::UnsupportedMember {
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
    ) -> Result<Option<ActiveWriter>, ExtractError> {
        self.ensure_new_path(&member.path).await?;
        let std_file = self
            .create_new_file(&member.path, member.executable, false)
            .await?;
        self.entries.insert(
            member.path.clone(),
            EntryKind::File {
                executable: member.executable,
            },
        );
        Ok(active_writer(member, std_file))
    }

    async fn create_directory(&mut self, member: DecodedMember) -> Result<(), ExtractError> {
        self.ensure_parents(&member.path).await?;
        if let Some(entry) = self.entries.get_mut(&member.path) {
            return match entry {
                EntryKind::Directory { declared: false } => {
                    *entry = EntryKind::Directory { declared: true };
                    Ok(())
                }
                _ => Err(ExtractError::PathCollision { path: member.path }),
            };
        }
        self.reject_existing(&member.path).await?;
        self.create_dir(&member.path).await?;
        self.entries
            .insert(member.path, EntryKind::Directory { declared: true });
        Ok(())
    }

    async fn reserve_symlink(&mut self, member: DecodedMember) -> Result<(), ExtractError> {
        let target_text = required_link_target(&member)?;
        let target = normalize_symlink_target(member.position, &member.path, &target_text)?;
        self.ensure_new_path(&member.path).await?;
        let contents = relative_link_contents(&member.path, &target);
        self.entries.insert(
            member.path.clone(),
            EntryKind::SymbolicLink(PendingSymlink {
                position: member.position,
                target_text,
                target,
                contents,
            }),
        );
        self.symlinks.push(member.path);
        Ok(())
    }

    async fn create_hard_link(
        &mut self,
        member: DecodedMember,
    ) -> Result<Option<ActiveWriter>, ExtractError> {
        let target_text = required_link_target(&member)?;
        let target = normalize_hard_link_target(member.position, &target_text)?;
        let target_executable = match self.entries.get(&target) {
            Some(EntryKind::File { executable }) => *executable,
            _ => {
                return Err(ExtractError::InvalidLink {
                    position: member.position,
                    path: member.path,
                    target: target_text,
                    reason: "hard-link target is not a previously extracted file",
                });
            }
        };
        if target_executable != member.executable {
            return Err(ExtractError::HardLinkExecutableMismatch {
                position: member.position,
                path: member.path,
                target,
            });
        }
        self.ensure_new_path(&member.path).await?;
        self.hard_link(&target, &member.path).await?;
        self.entries.insert(
            member.path.clone(),
            EntryKind::File {
                executable: member.executable,
            },
        );
        if member.payload_size == 0 {
            return Ok(None);
        }
        let std_file = self
            .create_new_file(&member.path, member.executable, true)
            .await?;
        Ok(active_writer(member, std_file))
    }

    async fn install_symlinks(&self) -> Result<(), ExtractError> {
        let mut terminal_kinds = Vec::with_capacity(self.symlinks.len());
        for path in &self.symlinks {
            let EntryKind::SymbolicLink(link) = self.entries.get(path).expect("tracked symlink")
            else {
                unreachable!("symlink list contains only symbolic links");
            };
            let kind = self
                .resolve_terminal(&link.target, &mut HashSet::new())
                .map_err(|reason| ExtractError::InvalidLink {
                    position: link.position,
                    path: path.clone(),
                    target: link.target_text.clone(),
                    reason,
                })?;
            terminal_kinds.push((path.clone(), link.clone(), kind));
        }

        for (path, link, kind) in terminal_kinds {
            self.install_symlink(&path, &link.contents, kind).await?;
        }
        Ok(())
    }

    fn resolve_terminal(
        &self,
        path: &Path,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<TerminalKind, &'static str> {
        if !visited.insert(path.to_owned()) {
            return Err("symbolic-link target cycle");
        }
        let components: Vec<_> = path.components().collect();
        let mut prefix = PathBuf::new();
        for (index, component) in components.iter().enumerate() {
            prefix.push(component.as_os_str());
            if let Some(EntryKind::SymbolicLink(link)) = self.entries.get(&prefix) {
                let mut rewritten = link.target.clone();
                for remainder in components.iter().skip(index + 1) {
                    rewritten.push(remainder.as_os_str());
                }
                return self.resolve_terminal(&rewritten, visited);
            }
        }
        match self.entries.get(path) {
            Some(EntryKind::File { .. }) => Ok(TerminalKind::File),
            Some(EntryKind::Directory { .. }) => Ok(TerminalKind::Directory),
            Some(EntryKind::SymbolicLink(_)) => unreachable!("handled while scanning prefixes"),
            None => Err("target was not created by this extraction"),
        }
    }

    async fn ensure_new_path(&mut self, path: &Path) -> Result<(), ExtractError> {
        self.ensure_parents(path).await?;
        if self.entries.contains_key(path) {
            return Err(ExtractError::PathCollision {
                path: path.to_owned(),
            });
        }
        self.reject_existing(path).await
    }

    async fn ensure_parents(&mut self, path: &Path) -> Result<(), ExtractError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        let mut current = PathBuf::new();
        for component in parent.components() {
            current.push(component.as_os_str());
            match self.entries.get(&current) {
                Some(EntryKind::Directory { .. }) => continue,
                Some(_) => {
                    return Err(ExtractError::PathCollision {
                        path: current.clone(),
                    });
                }
                None => {}
            }
            match self.symlink_metadata(&current).await? {
                Some(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Some(_) => {
                    return Err(ExtractError::PathCollision {
                        path: current.clone(),
                    });
                }
                None => {
                    self.create_dir(&current).await?;
                    self.entries
                        .insert(current.clone(), EntryKind::Directory { declared: false });
                }
            }
        }
        Ok(())
    }

    async fn reject_existing(&self, path: &Path) -> Result<(), ExtractError> {
        if self.symlink_metadata(path).await?.is_some() {
            Err(ExtractError::PathCollision {
                path: path.to_owned(),
            })
        } else {
            Ok(())
        }
    }

    async fn symlink_metadata(
        &self,
        path: &Path,
    ) -> Result<Option<cap_std::fs::Metadata>, ExtractError> {
        let relative = path.to_owned();
        let error_path = relative.clone();
        let dir = Arc::clone(&self.dir);
        match tokio::task::spawn_blocking(move || dir.symlink_metadata(relative)).await? {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(filesystem("inspect", error_path, source)),
        }
    }

    async fn create_dir(&self, path: &Path) -> Result<(), ExtractError> {
        let relative = path.to_owned();
        let error_path = relative.clone();
        let dir = Arc::clone(&self.dir);
        tokio::task::spawn_blocking(move || dir.create_dir(relative))
            .await?
            .map_err(|source| filesystem("create directory", error_path, source))
    }

    async fn create_new_file(
        &self,
        path: &Path,
        executable: bool,
        truncate: bool,
    ) -> Result<std::fs::File, ExtractError> {
        let relative = path.to_owned();
        let error_path = relative.clone();
        let dir = Arc::clone(&self.dir);
        tokio::task::spawn_blocking(move || {
            let mut options = OpenOptions::new();
            options.write(true);
            if truncate {
                options.truncate(true);
            } else {
                options.create_new(true);
            }
            let file = dir.open_with(relative, &options)?;
            add_executable(&file, executable)?;
            Ok(file.into_std())
        })
        .await?
        .map_err(|source| filesystem("create file", error_path, source))
    }

    async fn hard_link(&self, target: &Path, path: &Path) -> Result<(), ExtractError> {
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
    ) -> Result<(), ExtractError> {
        let path = path.to_owned();
        let error_path = path.clone();
        let contents = contents.to_owned();
        let dir = Arc::clone(&self.dir);
        tokio::task::spawn_blocking(move || create_symlink(&dir, &contents, &path, kind))
            .await?
            .map_err(|source| filesystem("create symbolic link", error_path, source))
    }
}

fn required_link_target(member: &DecodedMember) -> Result<String, ExtractError> {
    match member.link_target.clone() {
        Some(target) if !target.is_empty() => Ok(target),
        _ => Err(ExtractError::InvalidLink {
            position: member.position,
            path: member.path.clone(),
            target: String::new(),
            reason: "link target is empty",
        }),
    }
}

fn filesystem(operation: &'static str, path: PathBuf, source: io::Error) -> ExtractError {
    ExtractError::Filesystem {
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
    async fn write_frame(&mut self, frame: DataFrame) -> Result<bool, ExtractError> {
        let len = u64::try_from(frame.len).expect("data-frame lengths fit in u64");
        if len > self.remaining {
            return Err(ExtractError::InvalidFrameSequence {
                reason: "member payload exceeded the decoded member size",
            });
        }
        self.file
            .write_all(&frame.block[..frame.len])
            .await
            .map_err(|source| filesystem("write file", self.path.clone(), source))?;
        self.remaining -= len;
        if self.remaining == 0 {
            self.file
                .flush()
                .await
                .map_err(|source| filesystem("flush file", self.path.clone(), source))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn active_writer(member: DecodedMember, file: std::fs::File) -> Option<ActiveWriter> {
    (member.payload_size != 0).then(|| ActiveWriter {
        path: member.path,
        remaining: member.payload_size,
        file: tokio::fs::File::from_std(file),
    })
}

#[derive(Clone, Copy)]
enum TerminalKind {
    File,
    Directory,
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
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use super::*;
    use tar_framing::BLOCK_SIZE;
    use tempfile::tempdir;
    use tokio::io::ReadBuf;

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
    ) -> [u8; BLOCK_SIZE] {
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

    fn set_checksum(block: &mut [u8; BLOCK_SIZE]) {
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

    fn append_block(bytes: &mut Vec<u8>, block: &[u8; BLOCK_SIZE]) {
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

    async fn extract(bytes: Vec<u8>, dest: &Path) -> Result<(), ExtractError> {
        extract_with_policy(bytes, dest, ExtractPolicy::default()).await
    }

    async fn extract_with_policy(
        bytes: Vec<u8>,
        dest: &Path,
        policy: ExtractPolicy,
    ) -> Result<(), ExtractError> {
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
            use std::os::unix::fs::PermissionsExt;

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
    async fn applies_posix_path_and_linkpath_precedence() {
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

        extract(bytes, &dest).await.unwrap();
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
    async fn rejects_unsafe_paths_collisions_and_unsupported_members() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("occupied"), "keep").unwrap();

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
                "unsafe" => assert!(matches!(error, ExtractError::UnsafePath { .. })),
                "collision" => assert!(matches!(error, ExtractError::PathCollision { .. })),
                "unsupported" => assert!(matches!(error, ExtractError::UnsupportedMember { .. })),
                _ => unreachable!(),
            }
        }
        assert_eq!(
            std::fs::read_to_string(dest.join("occupied")).unwrap(),
            "keep"
        );
        assert!(!temp.path().join("escape").exists());

        let duplicate_dest = temp.path().join("duplicates");
        let mut duplicate = Vec::new();
        append_posix_member(&mut duplicate, "nested/../same", b'0', b"one", "", 0o644);
        append_posix_member(&mut duplicate, "same", b'0', b"two", "", 0o644);
        finish(&mut duplicate);
        assert!(matches!(
            extract(duplicate, &duplicate_dest).await.unwrap_err(),
            ExtractError::PathCollision { .. }
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_preexisting_symlink_parents() {
        use std::os::unix::fs::symlink;

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
            ExtractError::PathCollision { .. }
        ));
        assert!(!outside.join("file").exists());
    }

    #[tokio::test]
    async fn creates_safe_symlink_chains_and_rejects_dangling_links() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("good");
        let mut bytes = Vec::new();
        append_posix_member(&mut bytes, "dir/file", b'0', b"ok", "", 0o644);
        append_posix_member(&mut bytes, "dir/one", b'2', b"", "file", 0o644);
        append_posix_member(&mut bytes, "two", b'2', b"", "dir/one", 0o644);
        finish(&mut bytes);
        extract(bytes, &dest).await.unwrap();
        assert_eq!(std::fs::read_to_string(dest.join("two")).unwrap(), "ok");

        let bad_dest = temp.path().join("bad");
        let mut dangling = Vec::new();
        append_posix_member(&mut dangling, "link", b'2', b"", "missing", 0o644);
        finish(&mut dangling);
        assert!(matches!(
            extract(dangling, &bad_dest).await.unwrap_err(),
            ExtractError::InvalidLink { .. }
        ));
        assert!(!bad_dest.join("link").exists());

        let cycle_dest = temp.path().join("cycle");
        let mut cycle = Vec::new();
        append_posix_member(&mut cycle, "a", b'2', b"", "b", 0o644);
        append_posix_member(&mut cycle, "b", b'2', b"", "a", 0o644);
        finish(&mut cycle);
        assert!(matches!(
            extract(cycle, &cycle_dest).await.unwrap_err(),
            ExtractError::InvalidLink { .. }
        ));
        assert!(!cycle_dest.join("a").exists());
        assert!(!cycle_dest.join("b").exists());
    }

    #[tokio::test]
    async fn extracts_prior_target_hard_links_with_linkdata() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let policy = ExtractPolicy::default().allow_hard_links(true);
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
            ExtractError::InvalidLink { .. }
        ));

        let mismatch_dest = temp.path().join("mismatch");
        let mut mismatch = Vec::new();
        append_posix_member(&mut mismatch, "a", b'0', b"", "", 0o644);
        append_posix_member(&mut mismatch, "b", b'1', b"", "a", 0o755);
        finish(&mut mismatch);
        assert!(matches!(
            extract_with_policy(mismatch, &mismatch_dest, policy)
                .await
                .unwrap_err(),
            ExtractError::HardLinkExecutableMismatch { .. }
        ));
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
                ExtractPolicy::default().allow_symlinks(false)
            )
            .await
            .unwrap_err(),
            ExtractError::PolicyViolation {
                position: 1024,
                violation: ExtractPolicyViolation::SymbolicLink,
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
            ExtractError::PolicyViolation {
                position: 0,
                violation: ExtractPolicyViolation::HardLink,
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
            extract_with_policy(bytes, &dest, ExtractPolicy::default().allow_gnu(false))
                .await
                .unwrap_err(),
            ExtractError::PolicyViolation {
                position: 0,
                violation: ExtractPolicyViolation::GnuArchive,
            }
        ));
        assert!(!dest.join("renamed").exists());

        let empty_dest = temp.path().join("empty");
        let mut empty = Vec::new();
        finish(&mut empty);
        extract_with_policy(
            empty,
            &empty_dest,
            ExtractPolicy::default().allow_gnu(false),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rejects_every_pax_vendor_record_by_default() {
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
                extract(bytes, &dest).await.unwrap_err(),
                ExtractError::PolicyViolation {
                    position: 0,
                    violation: ExtractPolicyViolation::PaxVendorExtension {
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
            extract(partial, &partial_dest).await.unwrap_err(),
            ExtractError::PolicyViolation {
                position: 1024,
                violation: ExtractPolicyViolation::PaxVendorExtension { .. },
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
            ExtractPolicy::default().allow_pax_vendor_extensions(true),
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
            ExtractError::PolicyViolation {
                position: 0,
                violation: ExtractPolicyViolation::DuplicatePaxRecord { keyword },
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
            ExtractPolicy::default().allow_duplicate_pax_records(true),
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
    async fn permits_later_global_pax_headers_to_update_effective_values() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out");
        let mut bytes = Vec::new();
        append_pax(&mut bytes, b'g', &record("path", "old"));
        append_pax(&mut bytes, b'g', &record("path", "current"));
        append_posix_member(&mut bytes, "raw", b'0', b"contents", "", 0o644);
        finish(&mut bytes);

        extract(bytes, &dest).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("current")).unwrap(),
            "contents"
        );
        assert!(!dest.join("old").exists());
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
            ExtractError::DeletedPaxMetadata { .. }
        ));

        let gnu_dest = temp.path().join("gnu");
        let mut malformed_gnu = Vec::new();
        append_gnu_member(&mut malformed_gnu, "longname", b'L', b"no-nul", "", 0o644);
        append_gnu_member(&mut malformed_gnu, "raw", b'0', b"", "", 0o644);
        finish(&mut malformed_gnu);
        assert!(matches!(
            extract(malformed_gnu, &gnu_dest).await.unwrap_err(),
            ExtractError::InvalidGnuMetadata { .. }
        ));

        let utf8_dest = temp.path().join("utf8");
        let mut invalid_utf8 = header(POSIX_IDENTITY, "name", b'0', 0, "", 0o644);
        invalid_utf8[NAME_RANGE.start] = 0xff;
        set_checksum(&mut invalid_utf8);
        let mut invalid_utf8_archive = invalid_utf8.to_vec();
        finish(&mut invalid_utf8_archive);
        assert!(matches!(
            extract(invalid_utf8_archive, &utf8_dest).await.unwrap_err(),
            ExtractError::InvalidUtf8 { .. }
        ));

        let mode_dest = temp.path().join("mode");
        let mut invalid_mode = header(POSIX_IDENTITY, "mode", b'0', 0, "", 0o644);
        invalid_mode[MODE_RANGE].copy_from_slice(b"0000080\0");
        set_checksum(&mut invalid_mode);
        let mut invalid_mode_archive = invalid_mode.to_vec();
        finish(&mut invalid_mode_archive);
        assert!(matches!(
            extract(invalid_mode_archive, &mode_dest).await.unwrap_err(),
            ExtractError::InvalidMode { .. }
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
            ExtractError::Framing(_)
        ));
        assert_eq!(
            std::fs::read_to_string(partial_dest.join("created")).unwrap(),
            "kept"
        );
    }
}
