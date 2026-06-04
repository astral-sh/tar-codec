//! Secure high-level decoding and extraction for validated tar streams.
//!
//! `tar-codec` interprets member metadata above [`tar_framing`] and extracts
//! archive contents beneath a validated destination root. Decompression is
//! the caller's responsibility. Extraction requires a [`DecodePolicy`] so
//! that security-sensitive archive features are explicit at each call site.
//! Effective member and link bytes are legalized and normalized before they
//! enter extraction state.

use std::{borrow::Cow, collections::HashSet, io, path::PathBuf};

use tar_framing::{
    ArchiveFormat, FrameError, MemberKind, PaxKind, PaxRecord,
    logical::{MemberExtensions, MemberFrame, TarReader},
};
use thiserror::Error;
use tokio::io::AsyncRead;

use crate::paths::{LegalizedPath, NormalizedPath, PathError};

mod extract;

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
/// See each allow API for its default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodePolicy {
    allow_symlinks: bool,
    allow_dangling_symlinks: bool,
    allow_hard_links: bool,
    allow_overwrites: bool,
    allow_gnu: bool,
    pax_policy: PaxDecodePolicy,
}

/// Controls which otherwise valid pax features extraction may accept.
///
///
/// See each allow API for its default.
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
            allow_overwrites: true,
            allow_gnu: true,
            pax_policy: PaxDecodePolicy::default(),
        }
    }
}

impl DecodePolicy {
    /// Configures whether symbolic-link members may be extracted.
    ///
    /// Symlink extraction is **allowed by default**.
    pub fn allow_symlinks(mut self, allow: bool) -> Self {
        self.allow_symlinks = allow;
        self
    }

    /// Configures whether symbolic links may name safe targets other than
    /// entries created by this extraction or the extraction root.
    ///
    /// Dangling symlinks are **allowed by default** as they do not typically
    /// pose a security risk.
    pub fn allow_dangling_symlinks(mut self, allow: bool) -> Self {
        self.allow_dangling_symlinks = allow;
        self
    }

    /// Configures whether hard-link members may be extracted.
    ///
    /// Hardlinks are **forbidden by default** because they're (1) not common,
    /// (2) harder to extract in a cross-platform manner, and
    /// (3) may be differential-prone dependending on the input.
    ///
    /// **IMPORTANT**: Only enable hard-link extraction if you fully
    /// trust the archive you're extracting from.
    pub fn allow_hard_links(mut self, allow: bool) -> Self {
        self.allow_hard_links = allow;
        self
    }

    /// Configures whether archive members may replace existing destination
    /// entries.
    ///
    /// Overwrites during extraction are **allowed by default**.
    ///
    /// Replacement never follows symbolic links or recursively removes
    /// non-empty directories. Real directories are always reused, including
    /// when overwrites are disabled.
    pub fn allow_overwrites(mut self, allow: bool) -> Self {
        self.allow_overwrites = allow;
        self
    }

    /// Configures whether archives in the GNU framing family may be extracted.
    ///
    /// GNU tar archives are **allowed by default**.
    ///
    /// Users who wish to parse strictly pax-confirming tar archives may wish to
    /// disable this setting.
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
            return Err(DecodeError::policy_violation(
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
            return Err(DecodeError::policy_violation(position, violation));
        }
        Ok(())
    }

    fn check_global_pax(&self, position: u64, records: &[PaxRecord]) -> Result<(), DecodeError> {
        self.pax_policy.check_global_pax_extension(position)?;
        self.pax_policy
            .check_pax_records(position, PaxKind::Global, records)
    }

    fn check_member<R>(&self, frame: &MemberFrame<'_, R>) -> Result<(), DecodeError> {
        if let MemberExtensions::Pax(state) = &frame.extensions {
            for extension in state
                .extensions()
                .filter(|extension| extension.kind == PaxKind::Global)
            {
                self.check_global_pax(extension.position, extension.records())?;
            }
        }
        let format_position = match &frame.extensions {
            MemberExtensions::Pax(_) => frame.header.position,
            MemberExtensions::Gnu {
                long_name,
                long_link,
            } => long_name
                .iter()
                .chain(long_link.iter())
                .map(|header| header.position)
                .min()
                .unwrap_or(frame.header.position),
        };
        self.check_format(format_position, frame.header.format)?;
        self.check_member_kind(frame.header.position, frame.header.kind)?;
        if let MemberExtensions::Pax(state) = &frame.extensions {
            for extension in state
                .extensions()
                .filter(|extension| extension.kind == PaxKind::Local)
            {
                self.pax_policy.check_pax_records(
                    extension.position,
                    PaxKind::Local,
                    extension.records(),
                )?;
            }
        }
        Ok(())
    }
}

impl PaxDecodePolicy {
    /// Configures whether global pax extension headers may be accepted.
    ///
    /// When enabled, [`Self::allow_global_pax_member_metadata`] separately
    /// controls whether global `path`, `linkpath`, and `size` records are
    /// accepted. Trailing global headers without a following ordinary member
    /// are consumed and ignored before policy checks.
    ///
    /// Global pax extension headers are **allowed by default**.
    pub fn allow_global_pax_extensions(mut self, allow: bool) -> Self {
        self.allow_global_pax_extensions = allow;
        self
    }

    /// Configures whether vendor-namespaced pax records may be accepted.
    ///
    /// When enabled, well-formed vendor-namespaced pax records will not cause
    /// a decoding error.
    ///
    /// Vendor-namespaced pax records are **forbidden by default**.
    pub fn allow_pax_vendor_extensions(mut self, allow: bool) -> Self {
        self.allow_pax_vendor_extensions = allow;
        self
    }

    /// Configures whether one pax extended header may repeat a keyword.
    ///
    /// When enabled, standard pax precedence applies and the last record for
    /// a repeated keyword takes effect.
    ///
    /// Duplicated pax records within a single header are **forbidden by default**.
    pub fn allow_duplicate_pax_records(mut self, allow: bool) -> Self {
        self.allow_duplicate_pax_records = allow;
        self
    }

    /// Configures whether global pax headers may set member path or size data.
    ///
    /// When enabled, standard pax semantics permit global `path`, `linkpath`,
    /// and `size` records to apply to following members until overridden.
    ///
    /// Member metadata within global pax headers is **forbidden by default**,
    /// as it is extremely differential-prone.
    pub fn allow_global_pax_member_metadata(mut self, allow: bool) -> Self {
        self.allow_global_pax_member_metadata = allow;
        self
    }

    fn check_global_pax_extension(&self, position: u64) -> Result<(), DecodeError> {
        if !self.allow_global_pax_extensions {
            return Err(DecodeError::policy_violation(
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
                    return Err(DecodeError::policy_violation(
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
                    return Err(DecodeError::policy_violation(
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
                    return Err(DecodeError::policy_violation(
                        position,
                        DecodePolicyViolation::DuplicatePaxRecord { keyword },
                    ));
                }
            }
        }

        Ok(())
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
    /// A blocking extraction operation failed to complete.
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
    /// An archive entry collides with an existing path that cannot be replaced.
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

impl DecodeError {
    fn policy_violation(position: u64, violation: DecodePolicyViolation) -> Self {
        Self::PolicyViolation {
            position,
            violation,
        }
    }

    fn path_collision(path: PathBuf) -> Self {
        Self::PathCollision { path }
    }

    fn invalid_link(position: u64, path: PathBuf, target: String, reason: &'static str) -> Self {
        Self::InvalidLink {
            position,
            path,
            target,
            reason,
        }
    }

    fn unsafe_path(
        position: u64,
        context: &'static str,
        value: &str,
        reason: &'static str,
    ) -> Self {
        Self::UnsafePath {
            position,
            context,
            value: value.to_owned(),
            reason,
        }
    }

    fn filesystem(operation: &'static str, path: PathBuf, source: io::Error) -> Self {
        Self::Filesystem {
            operation,
            path,
            source,
        }
    }
}

#[derive(Debug)]
struct DecodedMember {
    position: u64,
    path: NormalizedPath,
    kind: MemberKind,
    link_target: Option<DecodedLinkTarget>,
    executable: bool,
    payload_size: u64,
}

#[derive(Debug)]
struct DecodedLinkTarget {
    path: NormalizedPath,
    text: String,
}

impl DecodedMember {
    fn link_target(&self) -> Result<&DecodedLinkTarget, DecodeError> {
        self.link_target
            .as_ref()
            .ok_or(DecodeError::InvalidFrameSequence {
                reason: "link member is missing its decoded target",
            })
    }
}

fn decode_member<R>(frame: &MemberFrame<'_, R>) -> Result<DecodedMember, DecodeError> {
    let header = &frame.header;
    let mode = header.mode()?;
    let executable = mode & 0o111 != 0;
    let path = legalized_path(
        header.position,
        "path",
        "member path",
        frame.effective_path()?,
    )?;
    let path = normalized_path(header.position, "member path", path)?;
    if path.is_empty() && header.kind != MemberKind::Directory {
        return Err(DecodeError::unsafe_path(
            header.position,
            "member path",
            ".",
            "only a directory may name the extraction root",
        ));
    }
    let link_target = if matches!(header.kind, MemberKind::HardLink | MemberKind::SymbolicLink) {
        let context = if header.kind == MemberKind::SymbolicLink {
            "symbolic-link target"
        } else {
            "hard-link target"
        };
        let target = legalized_path(
            header.position,
            "linkpath",
            context,
            frame.effective_link_path()?,
        )?;
        if target.as_str().is_empty() {
            return Err(DecodeError::invalid_link(
                header.position,
                path.to_path_buf(),
                String::new(),
                "link target is empty",
            ));
        }
        let text = target.as_str().to_owned();
        let target = if header.kind == MemberKind::SymbolicLink {
            path.resolve_from_parent(target)
        } else {
            target.normalize()
        };
        let target = target.map_err(|error| path_error(header.position, context, error))?;
        Some(DecodedLinkTarget { path: target, text })
    } else {
        None
    };

    Ok(DecodedMember {
        position: header.position,
        path,
        kind: header.kind,
        link_target,
        executable,
        payload_size: header.payload_size,
    })
}

fn legalized_path(
    position: u64,
    keyword: &'static str,
    context: &'static str,
    value: Cow<'_, [u8]>,
) -> Result<LegalizedPath, DecodeError> {
    LegalizedPath::from_bytes(value).map_err(|error| match error {
        PathError::InvalidUtf8 => DecodeError::InvalidUtf8 {
            position,
            field: keyword,
        },
        PathError::Unsafe { value, reason } => {
            DecodeError::unsafe_path(position, context, &value, reason)
        }
    })
}

fn normalized_path(
    position: u64,
    context: &'static str,
    path: LegalizedPath,
) -> Result<NormalizedPath, DecodeError> {
    path.normalize()
        .map_err(|error| path_error(position, context, error))
}

fn path_error(position: u64, context: &'static str, error: PathError) -> DecodeError {
    match error {
        PathError::InvalidUtf8 => DecodeError::InvalidUtf8 {
            position,
            field: context,
        },
        PathError::Unsafe { value, reason } => {
            DecodeError::unsafe_path(position, context, &value, reason)
        }
    }
}

fn relative_link_contents(link: &NormalizedPath, target: &NormalizedPath) -> PathBuf {
    let parent = link
        .as_str()
        .rfind('/')
        .map_or("", |separator| &link.as_str()[..separator]);
    let from: Vec<_> = parent
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
    let to: Vec<_> = target
        .as_str()
        .split('/')
        .filter(|component| !component.is_empty())
        .collect();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nonportable_paths_during_legalization() {
        let path = LegalizedPath::from_string("tests/snippets/ballon:main.py".to_owned())
            .and_then(LegalizedPath::normalize)
            .expect("ordinary colon should be accepted");
        assert_eq!(path.as_str(), "tests/snippets/ballon:main.py");
        for (value, reason) in [
            ("C:", "contains a platform path prefix"),
            ("C:/escape", "contains a platform path prefix"),
            ("nested/C:/escape", "contains a platform path prefix"),
            (
                "nested/\u{1f}",
                "contains an unacceptable character (NUL, ASCII control, or backslash)",
            ),
            ("nested/CON.txt", "contains a Windows reserved name"),
        ] {
            let result = LegalizedPath::from_string(value.to_owned())
                .and_then(LegalizedPath::normalize)
                .map_err(|error| path_error(0, "member path", error));
            assert!(matches!(
                result,
                Err(DecodeError::UnsafePath {
                    reason: actual_reason,
                    ..
                }) if actual_reason == reason
            ));
        }
    }
}
