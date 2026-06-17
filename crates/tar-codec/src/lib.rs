//! High-level decoding and encoding for tar archives.
//!
//! See [`decode`] for tar decoding, [`encode`] for pax encoding, and
//! [`Archive::extract_in`] for format-neutral extraction.
//!
//! ## Security
//!
//! Like other tar parsers, tar-codec assumes that it has unique access
//! to the target directory (the "extraction root") when extracting.
//! Concurrent mutation of the target directory is outside of the threat
//! model.
//! See the [repository's SECURITY.md](https://github.com/astral-sh/tar-codec/blob/main/SECURITY.md)
//! for more information.

mod blocking;
mod name;

pub mod decode;
pub mod encode;

pub use archive_trait::{
    Archive, ExtractError, ExtractPolicy, ExtractPolicyViolation, LentPayload, LinkPolicy, Member,
    MemberMetadata, MemberPayload, Members, NameValidator, SpecialKind, SymlinkPolicy,
    default_name_validator,
};
pub use decode::{
    DecodeError, DecodePolicy, DecodePolicyViolation, PaxDecodePolicy, TarArchive, TarMemberPayload,
};
