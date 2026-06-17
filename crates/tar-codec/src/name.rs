use archive_trait::{NameValidator, default_name_validator};

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
