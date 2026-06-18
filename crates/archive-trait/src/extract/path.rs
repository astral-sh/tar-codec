//! Member-name and link-target validation.

use std::path::{Component, Path, PathBuf};

use super::ExtractPolicy;
use crate::{ExtractError, Member};

/// The validated metadata needed while extracting one member.
#[derive(Debug)]
pub(super) struct ExtractMember {
    pub(super) position: u64,
    pub(super) path: PathBuf,
    pub(super) link_target: String,
}

/// Validates and normalizes the path-bearing fields of one member.
pub(super) fn decode_member<E, P>(
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

/// Converts archive path syntax into a contained, root-relative platform path.
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

/// A symbolic-link target normalized relative to its member path.
pub(super) struct ValidatedSymlinkTarget {
    pub(super) resolved_target: PathBuf,
    pub(super) requires_directory: bool,
}

/// Validates a symbolic-link target without resolving the archive link graph.
pub(super) fn validate_symlink_target<E>(
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

/// Applies platform-independent separator and absolute-path checks.
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

/// Resolves a lexical link target against `base` while enforcing containment.
pub(super) fn resolve_link_target<E>(
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
