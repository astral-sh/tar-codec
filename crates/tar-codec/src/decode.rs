//! Decoding and extraction of pax or GNU tar streams.

use std::{
    collections::HashSet,
    io,
    path::{Component, Path, PathBuf},
};

use tar_framing::{
    ArchiveFormat, FrameError, MemberKind, PaxKind, PaxRecord,
    logical::{MemberExtensions, MemberFrame, TarReader},
};
use thiserror::Error;
use tokio::io::AsyncRead;

use crate::{NameValidator, name::NameValidation};

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
#[derive(Clone, Copy, Debug)]
pub struct DecodePolicy {
    allow_symlinks: bool,
    allow_dangling_symlinks: bool,
    allow_hard_links: bool,
    allow_overwrites: bool,
    allow_gnu: bool,
    pax_policy: PaxDecodePolicy,
    name_validation: NameValidation,
}

/// Controls which otherwise valid pax features extraction may accept.
///
///
/// See each allow API for its default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaxDecodePolicy {
    allow_global_pax_extensions: bool,
    allow_unknown_pax_vendor_records: bool,
    allow_duplicate_pax_records: bool,
    allow_global_pax_member_metadata: bool,
}

impl Default for PaxDecodePolicy {
    fn default() -> Self {
        Self {
            allow_global_pax_extensions: true,
            allow_unknown_pax_vendor_records: false,
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
            name_validation: NameValidation::Default,
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

    /// Configures validation for member names and link targets.
    ///
    /// Passing [`None`] disables configurable name validation. UTF-8 and
    /// extraction containment requirements still apply.
    pub fn name_validator(mut self, validator: Option<NameValidator>) -> Self {
        self.name_validation = NameValidation::from_validator(validator);
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

    fn check_name(
        &self,
        position: u64,
        context: &'static str,
        value: &str,
    ) -> Result<(), DecodeError> {
        if !self.name_validation.accepts(value) {
            return Err(DecodeError::policy_violation(
                position,
                DecodePolicyViolation::NameRejected {
                    context,
                    value: value.to_owned(),
                },
            ));
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

    /// Configures whether unknown vendor-namespaced pax records may be accepted.
    ///
    /// When enabled, well-formed vendor-namespaced pax records do not cause a
    /// decoding error. Their values are parsed structurally but their semantics
    /// are not interpreted or validated.
    ///
    /// This can produce output that differs from the archive's intended
    /// contents. For example, `GNU.sparse.*` records can change a member's
    /// effective name, logical size, and mapping from stored payload bytes to
    /// file contents; these semantics are ignored when this option is enabled.
    ///
    /// **IMPORTANT**: Only enable this when silently ignoring unknown vendor
    /// semantics is acceptable. Unknown vendor-namespaced pax records are
    /// **forbidden by default**.
    pub fn allow_unknown_pax_vendor_records(mut self, allow: bool) -> Self {
        self.allow_unknown_pax_vendor_records = allow;
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
        if !self.allow_unknown_pax_vendor_records {
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
    /// An effective member name or link target was rejected by the configured validator.
    #[error("archive {context} rejected by name policy: {value:?}")]
    NameRejected {
        /// The role of the rejected archive text.
        context: &'static str,
        /// The rejected UTF-8 value.
        value: String,
    },
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
    effective_size: u64,
}

fn decode_member<R>(
    frame: &MemberFrame<'_, R>,
    policy: &DecodePolicy,
) -> Result<DecodedMember, DecodeError> {
    let header = &frame.header;
    let mode = header.mode()?;
    let executable = mode & 0o111 != 0;
    let path_text = std::str::from_utf8(frame.effective_path()?.as_ref())
        .map(str::to_owned)
        .map_err(|_| DecodeError::InvalidUtf8 {
            position: header.position,
            field: "path",
        })?;
    policy.check_name(header.position, "member path", &path_text)?;

    // This is a conservative choice: some other decoders treat a trailing slash
    // on a regular file as a signal to make a directory, while others silently
    // strip it and create a regular file instead. The former is consistent
    // with pre-ustar ("v7 tar") behavior, but is ambiguous in a ustar/pax/GNU
    // setting.
    // TODO: Make this configurable through policy?
    if path_text.ends_with('/') && header.kind != MemberKind::Directory {
        return Err(DecodeError::unsafe_path(
            header.position,
            "member path",
            &path_text,
            "only a directory may have a trailing separator",
        ));
    }
    let path = normalize_member_path(header.position, &path_text)?;
    if path.as_os_str().is_empty() && header.kind != MemberKind::Directory {
        return Err(DecodeError::unsafe_path(
            header.position,
            "member path",
            &path_text,
            "only a directory may resolve to the extraction root",
        ));
    }
    let link_target = if matches!(header.kind, MemberKind::HardLink | MemberKind::SymbolicLink) {
        let target = std::str::from_utf8(frame.effective_link_path()?.as_ref())
            .map(str::to_owned)
            .map_err(|_| DecodeError::InvalidUtf8 {
                position: header.position,
                field: "linkpath",
            })?;
        let context = if header.kind == MemberKind::SymbolicLink {
            "symbolic-link target"
        } else {
            "hard-link target"
        };
        policy.check_name(header.position, context, &target)?;
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
        effective_size: header.effective_size,
    })
}

fn normalize_member_path(position: u64, value: &str) -> Result<PathBuf, DecodeError> {
    validate_extraction_path(position, "member path", value)?;
    let mut path = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Prefix(_) => {
                return Err(DecodeError::unsafe_path(
                    position,
                    "member path",
                    value,
                    "contains a platform path prefix",
                ));
            }
            Component::RootDir => {
                return Err(DecodeError::unsafe_path(
                    position,
                    "member path",
                    value,
                    "is absolute",
                ));
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(DecodeError::unsafe_path(
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

/// A validated symbolic-link target represented in both coordinate systems
/// needed during extraction.
struct NormalizedSymlinkTarget {
    /// Normalized contents interpreted by the filesystem relative to the
    /// symbolic link's parent.
    link_contents: PathBuf,
    /// The same target resolved relative to the extraction root, used for
    /// containment and symbolic-link graph validation.
    resolved_target: PathBuf,
}

/// Normalizes and resolves a symbolic-link target without changing its base.
///
/// [`NormalizedSymlinkTarget::link_contents`] preserves the target as a
/// parent-relative link value, while [`NormalizedSymlinkTarget::resolved_target`]
/// identifies its destination relative to the extraction root. For example,
/// `../file` on a link at `dir/link` remains `../file` as link contents and
/// resolves to `file`.
///
/// Absolute, platform-prefixed, and escaping targets are rejected.
fn normalize_symlink_target(
    position: u64,
    path: &Path,
    value: &str,
) -> Result<NormalizedSymlinkTarget, DecodeError> {
    validate_extraction_path(position, "symbolic-link target", value)?;
    let base = path.parent().unwrap_or_else(|| Path::new(""));
    let mut contents = PathBuf::new();
    let mut resolved = base.to_owned();
    for component in Path::new(value).components() {
        match component {
            Component::Prefix(_) => {
                return Err(DecodeError::unsafe_path(
                    position,
                    "symbolic-link target",
                    value,
                    "contains a platform path prefix",
                ));
            }
            Component::RootDir => {
                return Err(DecodeError::unsafe_path(
                    position,
                    "symbolic-link target",
                    value,
                    "is absolute",
                ));
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(
                    contents.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    contents.pop();
                } else {
                    contents.push("..");
                }
                if !resolved.pop() {
                    return Err(DecodeError::unsafe_path(
                        position,
                        "symbolic-link target",
                        value,
                        "escapes the destination root",
                    ));
                }
            }
            Component::Normal(component) => {
                contents.push(component);
                resolved.push(component);
            }
        }
    }
    if contents.as_os_str().is_empty() {
        contents.push(".");
    }
    Ok(NormalizedSymlinkTarget {
        link_contents: contents,
        resolved_target: resolved,
    })
}

/// Reject absolute paths, as well as any path containing backslashes.
///
/// The latter effectively rejects Windows-style paths.
fn validate_extraction_path(
    position: u64,
    context: &'static str,
    value: &str,
) -> Result<(), DecodeError> {
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
    Ok(())
}

fn resolve_link_target(
    position: u64,
    context: &'static str,
    value: &str,
    base: &Path,
) -> Result<PathBuf, DecodeError> {
    validate_extraction_path(position, context, value)?;
    let mut path = base.to_owned();
    for component in Path::new(value).components() {
        match component {
            Component::Prefix(_) => {
                return Err(DecodeError::unsafe_path(
                    position,
                    context,
                    value,
                    "contains a platform path prefix",
                ));
            }
            Component::RootDir => {
                return Err(DecodeError::unsafe_path(
                    position,
                    context,
                    value,
                    "is absolute",
                ));
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !path.pop() {
                    return Err(DecodeError::unsafe_path(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_directory_components_in_member_paths() {
        for value in [
            "..",
            "../name",
            "name/..",
            "name/../other",
            "name//../other",
        ] {
            assert!(matches!(
                normalize_member_path(0, value),
                Err(DecodeError::UnsafePath {
                    context: "member path",
                    reason: "contains a parent-directory component",
                    ..
                })
            ));
        }
    }

    #[test]
    fn normalizes_symlink_contents_and_resolves_targets() {
        for (link, target, expected_contents, expected_resolved) in [
            ("link", "target", "target", "target"),
            ("nested/link", "../target", "../target", "target"),
            ("nested/link", "./target", "target", "nested/target"),
            ("a/b/link", "../c/target", "../c/target", "a/c/target"),
            ("nested/link", ".", ".", "nested"),
            ("nested/link", "a/../target", "target", "nested/target"),
        ] {
            let normalized = normalize_symlink_target(0, Path::new(link), target).unwrap();
            assert_eq!(normalized.link_contents, Path::new(expected_contents));
            assert_eq!(normalized.resolved_target, Path::new(expected_resolved));
        }
    }
}
