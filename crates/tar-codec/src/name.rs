/// A predicate that accepts or rejects one UTF-8 archive name.
pub type NameValidator = fn(&str) -> bool;

/// Applies the default archive name policy.
///
/// The default rejects ASCII control characters, including NUL and DEL, and
/// leading or trailing ASCII whitespace. It deliberately does not impose
/// extraction containment rules such as rejecting absolute paths or parent
/// components.
#[inline]
pub fn default_name_validator(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.iter().any(u8::is_ascii_control)
        && !bytes.first().is_some_and(u8::is_ascii_whitespace)
        && !bytes.last().is_some_and(u8::is_ascii_whitespace)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NameValidation {
    /// Our default name validator.
    ///
    /// Note that this is a distinct variant rather than being a
    /// instantiation of `Custom` for performance reasons: this allows
    /// us to make a static call rather than an indirect one.
    Default,
    Disabled,
    Custom(NameValidator),
}

impl NameValidation {
    pub(crate) fn from_validator(validator: Option<NameValidator>) -> Self {
        match validator {
            Some(validator) => Self::Custom(validator),
            None => Self::Disabled,
        }
    }

    #[inline]
    pub(crate) fn accepts(self, name: &str) -> bool {
        match self {
            Self::Default => default_name_validator(name),
            Self::Disabled => true,
            Self::Custom(validator) => validator(name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_validator_rejects_ascii_controls_and_boundary_whitespace() {
        for byte in 0..=u8::MAX {
            let character = char::from(byte);
            let name = character.to_string();
            assert_eq!(
                default_name_validator(&name),
                !byte.is_ascii_control() && !byte.is_ascii_whitespace(),
                "byte {byte:#04x}"
            );
        }

        for name in [
            "",
            "/absolute",
            r"back\slash",
            ".",
            "..",
            "a//b",
            "interior space",
            "\u{a0}name\u{a0}",
        ] {
            assert!(default_name_validator(name), "{name:?}");
        }
        for name in [" leading", "trailing ", "\tname", "name\n", "inside\nname"] {
            assert!(!default_name_validator(name), "{name:?}");
        }
    }
}
