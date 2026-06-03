//! Secure high-level decoding and extraction for validated tar streams.
//!
//! `tar-codec` interprets member metadata above [`tar_framing`] and extracts
//! archive contents beneath a validated destination root. Decompression is
//! the caller's responsibility. Extraction requires a [`DecodePolicy`] so
//! that security-sensitive archive features are explicit at each call site.

use std::{
    borrow::Cow,
    collections::HashSet,
    io,
    path::{Component, Path, PathBuf},
};

use tar_framing::{
    ArchiveFormat, FrameError, MemberKind, PaxKind, PaxRecord,
    logical::{LogicalFrame, MemberExtensions, MemberFrame, TarReader},
};
use thiserror::Error;
use tokio::io::AsyncRead;

use crate::has_windows_prefix;

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
/// The default permits symbolic links, safe dangling symbolic links, either
/// supported framing family, and replacement of existing destination entries,
/// while rejecting hard links, global pax member metadata, vendor-namespaced
/// pax records, and repeated keywords.
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
            allow_overwrites: true,
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

    /// Configures whether archive members may replace existing destination
    /// entries.
    ///
    /// Replacement never follows symbolic links or recursively removes
    /// non-empty directories. Real directories are always reused, including
    /// when overwrites are disabled.
    pub fn allow_overwrites(mut self, allow: bool) -> Self {
        self.allow_overwrites = allow;
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
        let format_position = match &frame.extensions {
            MemberExtensions::Pax { .. } => frame.header.position,
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
        if let MemberExtensions::Pax {
            local_position: Some(position),
        } = &frame.extensions
        {
            self.pax_policy.check_pax_records(
                *position,
                PaxKind::Local,
                &frame.header.local_pax_records,
            )?;
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
    path: PathBuf,
    kind: MemberKind,
    link_target: String,
    executable: bool,
    payload_size: u64,
}

fn decode_member<R>(frame: &MemberFrame<'_, R>) -> Result<DecodedMember, DecodeError> {
    let header = &frame.header;
    let mode = header.mode()?;
    let executable = mode & 0o111 != 0;
    let path = resolved_text(header.position, "path", frame.effective_path()?)?;
    let path = normalize_member_path(header.position, &path)?;
    if path.as_os_str().is_empty() && header.kind != MemberKind::Directory {
        return Err(DecodeError::unsafe_path(
            header.position,
            "member path",
            ".",
            "only a directory may name the extraction root",
        ));
    }
    let link_target = if matches!(header.kind, MemberKind::HardLink | MemberKind::SymbolicLink) {
        let target = resolved_text(header.position, "linkpath", frame.effective_link_path()?)?;
        if target.is_empty() {
            return Err(DecodeError::invalid_link(
                header.position,
                path,
                target,
                "link target is empty",
            ));
        }
        target
    } else {
        String::new()
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
        return Err(DecodeError::unsafe_path(
            position,
            context,
            value,
            "contains a NUL byte",
        ));
    }
    if value.contains('\\') {
        return Err(DecodeError::unsafe_path(
            position,
            context,
            value,
            "contains a backslash separator",
        ));
    }
    if value.starts_with('/') {
        return Err(DecodeError::unsafe_path(
            position,
            context,
            value,
            "is absolute",
        ));
    }
    let mut components = base.to_vec();
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(DecodeError::unsafe_path(
                        position,
                        context,
                        value,
                        "escapes the destination root",
                    ));
                }
            }
            component if has_windows_prefix(component) => {
                return Err(DecodeError::unsafe_path(
                    position,
                    context,
                    value,
                    "contains a platform path prefix",
                ));
            }
            component => components.push(component.to_owned()),
        }
    }
    Ok(components.iter().collect())
}

fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(component) => Some(component.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
