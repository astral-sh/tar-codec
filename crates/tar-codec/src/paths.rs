//! Shared archive-path legalization and normalization.

use std::{
    borrow::{Borrow, Cow},
    mem::size_of,
    path::{Path, PathBuf},
};

use memchr::memchr3;

/// A UTF-8 archive path whose bytes are safe to interpret portably.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegalizedPath {
    value: String,
    normalized: bool,
}

/// A legalized archive path in canonical, root-relative form.
#[repr(transparent)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct NormalizedPath(String);

/// A failure while legalizing or normalizing an archive path.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PathError {
    /// The source path is not valid UTF-8.
    InvalidUtf8,
    /// The source path is unsafe or cannot be normalized beneath its root.
    Unsafe { value: String, reason: &'static str },
}

impl LegalizedPath {
    /// Legalizes effective header bytes while reusing owned PAX/GNU storage.
    pub(crate) fn from_bytes(value: Cow<'_, [u8]>) -> Result<Self, PathError> {
        let value = match value {
            Cow::Borrowed(value) => {
                let value = std::str::from_utf8(value).map_err(|_| PathError::InvalidUtf8)?;
                value.to_owned()
            }
            Cow::Owned(value) => String::from_utf8(value).map_err(|_| PathError::InvalidUtf8)?,
        };
        Self::from_string(value)
    }

    /// Legalizes a filesystem-facing archive path.
    pub(crate) fn from_path(path: &Path) -> Result<Self, PathError> {
        let Some(value) = path.to_str() else {
            return Err(PathError::InvalidUtf8);
        };
        Self::from_string(value.to_owned())
    }

    /// Legalizes an owned UTF-8 archive path.
    pub(crate) fn from_string(value: String) -> Result<Self, PathError> {
        if value.is_empty() {
            return Ok(Self {
                value,
                normalized: true,
            });
        }
        if contains_unsafe_ascii(value.as_bytes()) {
            return Err(PathError::Unsafe {
                value,
                reason: "contains an unacceptable character (NUL, ASCII control, or backslash)",
            });
        }
        let mut contains_platform_prefix = false;
        let mut contains_windows_reserved_name = false;
        let mut normalized = true;
        for component in value.as_bytes().split(|byte| *byte == b'/') {
            contains_platform_prefix |=
                component.len() >= 2 && component[0].is_ascii_alphabetic() && component[1] == b':';
            if component.first().is_some_and(|byte| {
                matches!(byte.to_ascii_uppercase(), b'A' | b'C' | b'L' | b'N' | b'P')
            }) {
                contains_windows_reserved_name |= is_windows_reserved_component(component);
            }
            normalized &= !matches!(component, [] | [b'.'] | [b'.', b'.']);
        }

        let reason = if value.starts_with('/') {
            Some("is absolute")
        } else if contains_platform_prefix {
            Some("contains a platform path prefix")
        } else if contains_windows_reserved_name {
            Some("contains a Windows reserved name")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(PathError::Unsafe { value, reason });
        }
        Ok(Self { value, normalized })
    }

    /// Returns the legalized path text.
    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    /// Consumes this path and returns its canonical root-relative form.
    pub(crate) fn normalize(self) -> Result<NormalizedPath, PathError> {
        self.normalize_with_base("")
    }

    fn normalize_with_base(self, base: &str) -> Result<NormalizedPath, PathError> {
        if self.normalized {
            if base.is_empty() {
                return Ok(NormalizedPath(self.value));
            }
            if self.value.is_empty() {
                return Ok(NormalizedPath(base.to_owned()));
            }
            let mut combined = String::with_capacity(base.len() + 1 + self.value.len());
            combined.push_str(base);
            combined.push('/');
            combined.push_str(&self.value);
            return Ok(NormalizedPath(combined));
        }
        if escapes_root(base, &self.value) {
            return Err(PathError::Unsafe {
                value: self.value,
                reason: "escapes the destination root",
            });
        }

        let mut value = if base.is_empty() {
            self.value
        } else if self.value.is_empty() {
            base.to_owned()
        } else {
            let mut combined = String::with_capacity(base.len() + 1 + self.value.len());
            combined.push_str(base);
            combined.push('/');
            combined.push_str(&self.value);
            combined
        };
        normalize_in_place(&mut value)?;
        Ok(NormalizedPath(value))
    }
}

fn contains_unsafe_ascii(bytes: &[u8]) -> bool {
    const ONES: u64 = u64::MAX / u8::MAX as u64;
    const HIGHS: u64 = ONES * 0x80;

    if memchr3(b'\0', b'\\', 0x7f, bytes).is_some() {
        return true;
    }
    let mut chunks = bytes.chunks_exact(size_of::<u64>());
    for chunk in &mut chunks {
        let Ok(chunk) = <&[u8; size_of::<u64>()]>::try_from(chunk) else {
            continue;
        };
        let word = u64::from_ne_bytes(*chunk);
        if has_byte_below(word, 0x20, ONES, HIGHS) {
            return true;
        }
    }
    chunks
        .remainder()
        .iter()
        .any(|byte| byte.is_ascii_control() || *byte == b'\\')
}

fn has_byte_below(value: u64, limit: u8, ones: u64, highs: u64) -> bool {
    // Detect a high borrow bit independently in each packed byte lane.
    value.wrapping_sub(ones * u64::from(limit)) & !value & highs != 0
}

fn is_windows_reserved_component(component: &[u8]) -> bool {
    let [first, second, third, suffix @ ..] = component else {
        return false;
    };
    let prefix = (
        first.to_ascii_uppercase(),
        second.to_ascii_uppercase(),
        third.to_ascii_uppercase(),
    );
    if matches!(
        prefix,
        (b'C', b'O', b'N') | (b'P', b'R', b'N') | (b'A', b'U', b'X') | (b'N', b'U', b'L')
    ) {
        return suffix.first().is_none_or(|byte| *byte == b'.');
    }
    if !matches!(prefix, (b'C', b'O', b'M') | (b'L', b'P', b'T')) {
        return false;
    }
    match suffix {
        [digit, extension @ ..] if matches!(*digit, b'1'..=b'9') => {
            extension.first().is_none_or(|byte| *byte == b'.')
        }
        [0xc2, digit, extension @ ..] if matches!(*digit, 0xb9 | 0xb2 | 0xb3) => {
            extension.first().is_none_or(|byte| *byte == b'.')
        }
        _ => false,
    }
}

impl NormalizedPath {
    /// Returns the canonical portable path text.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns this archive path as a platform filesystem path.
    pub(crate) fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Returns whether this path names the archive root.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Creates the normalized archive root.
    pub(crate) fn root() -> Self {
        Self(String::new())
    }

    /// Appends one component taken from another normalized path.
    pub(crate) fn push_normalized_component(&mut self, component: &str) {
        if !self.0.is_empty() {
            self.0.push('/');
        }
        self.0.push_str(component);
    }

    /// Copies a component-aligned prefix from this normalized path.
    pub(crate) fn prefix(&self, end: usize) -> Self {
        Self(self.0[..end].to_owned())
    }

    /// Resolves a legalized symbolic-link target relative to this member's parent.
    pub(crate) fn resolve_from_parent(&self, target: LegalizedPath) -> Result<Self, PathError> {
        let base = self
            .0
            .rfind('/')
            .map_or("", |separator| &self.0[..separator]);
        target.normalize_with_base(base)
    }

    /// Returns whether `base` is this path or one of its component ancestors.
    pub(crate) fn starts_with(&self, base: &Self) -> bool {
        base.is_empty()
            || self == base
            || self
                .0
                .strip_prefix(&base.0)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    /// Appends an already-normalized non-empty suffix.
    pub(crate) fn join_normalized(&self, suffix: &str) -> Self {
        if self.is_empty() {
            return Self(suffix.to_owned());
        }
        if suffix.is_empty() {
            return self.clone();
        }
        let mut joined = String::with_capacity(self.0.len() + 1 + suffix.len());
        joined.push_str(&self.0);
        joined.push('/');
        joined.push_str(suffix);
        Self(joined)
    }

    /// Returns an owned filesystem path for public errors and I/O operations.
    pub(crate) fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(&self.0)
    }
}

impl Borrow<str> for NormalizedPath {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

fn escapes_root(base: &str, value: &str) -> bool {
    let mut depth = if base.is_empty() {
        0
    } else {
        base.bytes().filter(|byte| *byte == b'/').count() + 1
    };
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." if depth == 0 => return true,
            ".." => depth -= 1,
            _ => depth += 1,
        }
    }
    false
}

fn normalize_in_place(value: &mut String) -> Result<(), PathError> {
    let mut bytes = std::mem::take(value).into_bytes();
    let mut component_starts: Vec<usize> = Vec::new();
    let mut read = 0;
    let mut written = 0;

    while read <= bytes.len() {
        let end = bytes[read..]
            .iter()
            .position(|byte| *byte == b'/')
            .map_or(bytes.len(), |offset| read + offset);
        match &bytes[read..end] {
            [] | [b'.'] => {}
            [b'.', b'.'] => {
                if let Some(start) = component_starts.pop() {
                    written = start.saturating_sub(1);
                }
            }
            _ => {
                if written != 0 {
                    bytes[written] = b'/';
                    written += 1;
                }
                let start = written;
                bytes.copy_within(read..end, written);
                written += end - read;
                component_starts.push(start);
            }
        }
        if end == bytes.len() {
            break;
        }
        read = end + 1;
    }

    bytes.truncate(written);
    *value = String::from_utf8(bytes).map_err(|_| PathError::InvalidUtf8)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalize(value: &str) -> Result<String, PathError> {
        LegalizedPath::from_string(value.to_owned())
            .and_then(LegalizedPath::normalize)
            .map(|path| path.0)
    }

    #[test]
    fn legalizes_and_normalizes_paths() {
        for (value, expected) in [
            ("path", "path"),
            ("a//b", "a/b"),
            ("a/./b", "a/b"),
            ("a/x/../b", "a/b"),
            ("a/", "a"),
            (".", ""),
            ("a/..", ""),
        ] {
            assert_eq!(normalize(value), Ok(expected.to_owned()), "{value}");
        }
    }

    #[test]
    fn legalization_preserves_noncanonical_components() {
        let path =
            LegalizedPath::from_string("a//./b/../c".to_owned()).expect("path should legalize");
        assert_eq!(path.as_str(), "a//./b/../c");
    }

    #[test]
    fn rejects_unsafe_paths() {
        for (value, reason) in [
            (
                "\0",
                "contains an unacceptable character (NUL, ASCII control, or backslash)",
            ),
            (
                "\t",
                "contains an unacceptable character (NUL, ASCII control, or backslash)",
            ),
            (
                "\u{7f}",
                "contains an unacceptable character (NUL, ASCII control, or backslash)",
            ),
            (
                "a\\b",
                "contains an unacceptable character (NUL, ASCII control, or backslash)",
            ),
            ("/a", "is absolute"),
            ("C:/a", "contains a platform path prefix"),
            ("a/C:/b", "contains a platform path prefix"),
            ("CON", "contains a Windows reserved name"),
            ("nested/prn.txt", "contains a Windows reserved name"),
            ("AUX.tar.gz", "contains a Windows reserved name"),
            ("nul", "contains a Windows reserved name"),
            ("COM1", "contains a Windows reserved name"),
            ("com9.txt", "contains a Windows reserved name"),
            ("LPT1", "contains a Windows reserved name"),
            ("lpt9.log", "contains a Windows reserved name"),
            ("COM¹", "contains a Windows reserved name"),
            ("lpt³.txt", "contains a Windows reserved name"),
            ("../a", "escapes the destination root"),
            ("a/../../b", "escapes the destination root"),
        ] {
            assert_eq!(
                normalize(value),
                Err(PathError::Unsafe {
                    value: value.to_owned(),
                    reason,
                }),
                "{value}"
            );
        }
    }

    #[test]
    fn accepts_non_reserved_windows_name_prefixes() {
        for value in [
            "console",
            "printer",
            "auxiliary",
            "null",
            "COM0",
            "COM10",
            "LPT0",
            "LPT10",
            ".CON",
            "name.CON",
        ] {
            assert_eq!(normalize(value), Ok(value.to_owned()), "{value}");
        }
    }

    #[test]
    fn unsafe_ascii_scan_matches_scalar_classification() {
        for first in u8::MIN..=u8::MAX {
            for second in u8::MIN..=u8::MAX {
                let bytes = [b'a', b'b', b'c', first, second, b'x', b'y', b'z'];
                let expected = bytes
                    .iter()
                    .any(|byte| byte.is_ascii_control() || *byte == b'\\');
                assert_eq!(contains_unsafe_ascii(&bytes), expected, "{bytes:?}");
            }
        }
    }

    #[test]
    fn rejects_non_utf8_bytes() {
        assert_eq!(
            LegalizedPath::from_bytes(Cow::Borrowed(&[0xff])),
            Err(PathError::InvalidUtf8)
        );
    }

    #[test]
    fn resolves_paths_relative_to_member_parents() {
        let member = normalize("a/b/link").expect("member path should normalize");
        let member = NormalizedPath(member);
        for (value, expected) in [
            ("target", "a/b/target"),
            ("../target", "a/target"),
            ("../../target", "target"),
        ] {
            let target =
                LegalizedPath::from_string(value.to_owned()).expect("target should legalize");
            assert_eq!(
                member.resolve_from_parent(target).map(|path| path.0),
                Ok(expected.to_owned()),
                "{value}"
            );
        }

        let target = LegalizedPath::from_string("../../../target".to_owned())
            .expect("target should legalize");
        assert_eq!(
            member.resolve_from_parent(target),
            Err(PathError::Unsafe {
                value: "../../../target".to_owned(),
                reason: "escapes the destination root",
            })
        );
    }

    #[test]
    fn root_normalization_reuses_the_owned_buffer() {
        let value = Vec::from("a/./b".as_bytes());
        let pointer = value.as_ptr();
        let path = LegalizedPath::from_bytes(Cow::Owned(value))
            .and_then(LegalizedPath::normalize)
            .expect("path should normalize");
        assert_eq!(path.as_str(), "a/b");
        assert_eq!(path.as_str().as_ptr(), pointer);
    }
}
