//! High-level decoding and encoding for tar archives.
//!
//! See [`decode`] for tar decoding, [`encode`] for pax encoding,
//! [`Builder`] for format-neutral construction, and
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

pub mod decode;
pub mod encode;

pub use archive_trait::{
    Archive, ArchiveBuilder, BuildError, Builder, EntryMetadata, ExtractError,
    ExtractPolicyViolation, LentPayload, Member, MemberMetadata, MemberPayload, Members,
    NameValidator, SpecialKind, TraversalError, default_name_validator,
};
pub use archive_trait::{builder, extract};
pub use decode::{
    DecodeError, DecodePolicy, DecodePolicyViolation, PaxDecodePolicy, TarArchive, TarMemberPayload,
};
pub use encode::{EncodeError, TarEncoder};
