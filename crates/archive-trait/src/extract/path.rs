//! Member-name and link-target validation.

use std::path::{Component, Path, PathBuf};

use super::ExtractPolicy;
use crate::{ExtractError, Member};

/// The validated metadata needed while extracting one member.
#[derive(Debug)]
pub(super) struct ExtractMember {
    pub(super) position: u64,
    pub(super) path: NormalizedPath,
    pub(super) link_target: String,
}

/// A normalized, contained extraction path whose components are valid UTF-8.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub(super) struct NormalizedPath(String);

impl NormalizedPath {
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(super) fn components(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('/').filter(|component| !component.is_empty())
    }

    pub(super) fn parent_components(&self) -> impl Iterator<Item = &str> {
        let mut components = self.components();
        components.next_back();
        components
    }

    pub(super) fn parent(&self) -> Self {
        if let Some((parent, _)) = self.0.rsplit_once('/') {
            Self(parent.to_owned())
        } else {
            Self::default()
        }
    }

    pub(super) fn file_name(&self) -> Option<&str> {
        if self.is_empty() {
            None
        } else {
            self.0.rsplit('/').next()
        }
    }

    pub(super) fn push(&mut self, component: &str) {
        if !self.0.is_empty() {
            self.0.push('/');
        }
        self.0.push_str(component);
    }

    pub(super) fn pop(&mut self) -> bool {
        if let Some(separator) = self.0.rfind('/') {
            self.0.truncate(separator);
            true
        } else if self.0.is_empty() {
            false
        } else {
            self.0.clear();
            true
        }
    }

    pub(super) fn extend<'a>(&mut self, components: impl IntoIterator<Item = &'a str>) {
        for component in components {
            self.push(component);
        }
    }

    pub(super) fn starts_with(&self, base: &Self) -> bool {
        if base.is_empty() {
            return true;
        }
        self == base
            || self
                .0
                .strip_prefix(&base.0)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    pub(super) fn to_path_buf(&self) -> PathBuf {
        self.components().collect()
    }
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
    if path.is_empty() && !matches!(member, Member::Directory { .. }) {
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
            path.to_path_buf(),
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

/// Converts archive path syntax into a contained, root-relative UTF-8 path.
fn normalize_member_path<E>(position: u64, value: &str) -> Result<NormalizedPath, ExtractError<E>> {
    validate_extraction_path(position, "member path", value)?;
    let mut path = NormalizedPath::default();
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(ExtractError::unsafe_path(
                    position,
                    "member path",
                    value,
                    "contains a parent-directory component",
                ));
            }
            component => path.push(component),
        }
    }
    Ok(path)
}

/// A symbolic-link target normalized relative to its member path.
pub(super) struct ValidatedSymlinkTarget {
    pub(super) resolved_target: NormalizedPath,
    pub(super) requires_directory: bool,
}

/// Validates a symbolic-link target without resolving the archive link graph.
pub(super) fn validate_symlink_target<E>(
    position: u64,
    path: &NormalizedPath,
    value: &str,
) -> Result<ValidatedSymlinkTarget, ExtractError<E>> {
    validate_extraction_path(position, "symbolic-link target", value)?;
    let mut resolved = path.parent();
    let mut normal_component_seen = false;
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => {
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
            component => {
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
            _ => {}
        }
    }
    // Link resolution can move any component to the root of the normalized
    // path, where a drive-relative component would become a platform prefix.
    for component in value.split('/') {
        if matches!(
            Path::new(component).components().next(),
            Some(Component::Prefix(_) | Component::RootDir)
        ) {
            return Err(ExtractError::unsafe_path(
                position,
                context,
                value,
                "contains a platform path prefix",
            ));
        }
    }
    Ok(())
}

/// Resolves a lexical link target against `base` while enforcing containment.
pub(super) fn resolve_link_target<E>(
    position: u64,
    context: &'static str,
    value: &str,
    base: &NormalizedPath,
) -> Result<NormalizedPath, ExtractError<E>> {
    validate_extraction_path(position, context, value)?;
    let mut path = base.clone();
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if !path.pop() {
                    return Err(ExtractError::unsafe_path(
                        position,
                        context,
                        value,
                        "escapes the destination root",
                    ));
                }
            }
            component => path.push(component),
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_paths_preserve_utf8_and_canonical_components() {
        let path =
            normalize_member_path::<()>(0, "./α//β/.").expect("UTF-8 member path should normalize");

        assert_eq!(path.as_str(), "α/β");
        assert_eq!(path.components().collect::<Vec<_>>(), ["α", "β"]);
        assert_eq!(path.file_name(), Some("β"));
        assert_eq!(path.parent().as_str(), "α");
        assert_eq!(path.to_path_buf(), PathBuf::from("α").join("β"));

        let parent = normalize_member_path::<()>(0, "α").expect("parent should normalize");
        let sibling = normalize_member_path::<()>(0, "αβ").expect("sibling should normalize");
        assert!(path.starts_with(&parent));
        assert!(!path.starts_with(&sibling));
    }

    #[test]
    fn normalized_paths_reject_unsafe_syntax() {
        for value in ["../escape", "/absolute", r"back\slash"] {
            assert!(matches!(
                normalize_member_path::<()>(0, value),
                Err(ExtractError::UnsafePath { .. })
            ));
        }
    }

    #[test]
    fn link_resolution_uses_normalized_utf8_components() {
        let path =
            normalize_member_path::<()>(0, "dir/nested/link").expect("link path should normalize");
        let target = validate_symlink_target::<()>(0, &path, "../../target/")
            .expect("leading parent components should resolve");
        assert_eq!(target.resolved_target.as_str(), "target");
        assert!(target.requires_directory);

        assert!(matches!(
            validate_symlink_target::<()>(0, &path, "../target/.."),
            Err(ExtractError::UnsafePath { .. })
        ));
        assert!(matches!(
            validate_symlink_target::<()>(0, &path, "../../../escape"),
            Err(ExtractError::UnsafePath { .. })
        ));

        let base = normalize_member_path::<()>(0, "base").expect("base should normalize");
        let resolved = resolve_link_target::<()>(0, "hard-link target", "child/../other", &base)
            .expect("lexical hard-link target should resolve");
        assert_eq!(resolved.as_str(), "base/other");
    }

    #[cfg(windows)]
    #[test]
    fn normalized_paths_reject_windows_prefixes() {
        for value in ["C:relative", "C:/absolute", "dir/C:relative"] {
            assert!(matches!(
                normalize_member_path::<()>(0, value),
                Err(ExtractError::UnsafePath { .. })
            ));
        }

        let path = normalize_member_path::<()>(0, "dir/link").expect("link path should normalize");
        assert!(matches!(
            validate_symlink_target::<()>(0, &path, "../C:relative"),
            Err(ExtractError::UnsafePath { .. })
        ));
    }
}
