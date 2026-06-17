//! Format-neutral, asynchronous archive construction and extraction.
//!
//! Archive formats implement [`ArchiveBuilder`] and call
//! [`ArchiveBuilder::builder`] to reuse high-level entry addition, recursive
//! filesystem traversal, validation, and source streaming.
//! Archive formats implement [`Archive`] by projecting their entries into
//! [`Member`] values. The default [`Archive::extract_in`] implementation then
//! applies common extraction policy and filesystem behavior.
//!
//! Extraction assumes unique access to the destination directory. Concurrent
//! mutation of that directory is outside the threat model.

pub mod builder;
pub mod extract;
mod name;

use std::{
    io,
    marker::PhantomData,
    path::{Path, PathBuf},
};

use thiserror::Error;

pub use builder::{ArchiveBuilder, BuildError, Builder, EntryMetadata, TraversalError};
pub use name::{NameValidator, default_name_validator};

/// Common metadata for one archive member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberMetadata {
    /// The archive-relative member path before extraction normalization.
    pub path: String,
    /// The member's byte position in the source archive.
    pub position: u64,
}

/// A special-file kind that generic extraction deliberately rejects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpecialKind {
    /// A character device.
    CharacterDevice,
    /// A block device.
    BlockDevice,
    /// A FIFO.
    Fifo,
}

/// One format-neutral archive member.
#[derive(Debug)]
pub enum Member<P> {
    /// A regular file with a streaming payload.
    File {
        /// Common member metadata.
        metadata: MemberMetadata,
        /// The effective payload size.
        size: u64,
        /// Whether the archived mode carries executable intent.
        executable: bool,
        /// The streaming member payload.
        payload: P,
    },
    /// A directory.
    Directory {
        /// Common member metadata.
        metadata: MemberMetadata,
    },
    /// A symbolic link.
    SymbolicLink {
        /// Common member metadata.
        metadata: MemberMetadata,
        /// The archive-provided link target.
        target: String,
    },
    /// A hard link, optionally followed by replacement payload bytes.
    HardLink {
        /// Common member metadata.
        metadata: MemberMetadata,
        /// The archive-provided link target.
        target: String,
        /// The effective payload size.
        size: u64,
        /// The streaming member payload.
        payload: P,
    },
    /// A parsed special file that cannot be extracted safely.
    Special {
        /// Common member metadata.
        metadata: MemberMetadata,
        /// The special-file kind.
        kind: SpecialKind,
    },
}

impl<P> Member<P> {
    /// Returns this member's common metadata.
    pub fn metadata(&self) -> &MemberMetadata {
        match self {
            Self::File { metadata, .. }
            | Self::Directory { metadata }
            | Self::SymbolicLink { metadata, .. }
            | Self::HardLink { metadata, .. }
            | Self::Special { metadata, .. } => metadata,
        }
    }

    fn lend_payload<'a>(self) -> Member<LentPayload<'a, P>> {
        match self {
            Self::File {
                metadata,
                size,
                executable,
                payload,
            } => Member::File {
                metadata,
                size,
                executable,
                payload: LentPayload::new(payload),
            },
            Self::Directory { metadata } => Member::Directory { metadata },
            Self::SymbolicLink { metadata, target } => Member::SymbolicLink { metadata, target },
            Self::HardLink {
                metadata,
                target,
                size,
                payload,
            } => Member::HardLink {
                metadata,
                target,
                size,
                payload: LentPayload::new(payload),
            },
            Self::Special { metadata, kind } => Member::Special { metadata, kind },
        }
    }
}

/// A streaming cursor over one archive member's payload.
#[expect(
    async_fn_in_trait,
    reason = "payload readers may be !Send and run on a local executor"
)]
pub trait MemberPayload: Sized {
    /// The archive-format error returned while reading the payload.
    type Error;

    /// Reads the next validated payload chunk into a reusable buffer.
    ///
    /// Returns `true` when `buffer` contains a nonempty chunk. Returns `false`
    /// only after the payload has been fully consumed and validated. Callers
    /// clear `buffer` before each call, and implementations may return chunks
    /// shorter than `target_len`.
    async fn next_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, Self::Error>;

    /// Discards and validates all remaining payload bytes.
    async fn skip(self) -> Result<(), Self::Error>;
}

/// A member payload that keeps its lending [`Members`] cursor borrowed.
///
/// This wrapper is returned by [`Members::next`]. Its private fields prevent a
/// payload whose concrete type does not itself borrow the archive from being
/// detached from the cursor lifetime.
#[derive(Debug)]
pub struct LentPayload<'a, P> {
    payload: P,
    cursor: PhantomData<&'a mut ()>,
}

impl<P> LentPayload<'_, P> {
    fn new(payload: P) -> Self {
        Self {
            payload,
            cursor: PhantomData,
        }
    }
}

impl<P: MemberPayload> MemberPayload for LentPayload<'_, P> {
    type Error = P::Error;

    async fn next_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, Self::Error> {
        self.payload.next_chunk(buffer, target_len).await
    }

    async fn skip(self) -> Result<(), Self::Error> {
        self.payload.skip().await
    }
}

/// A consuming, lending member cursor.
pub struct Members<A> {
    archive: A,
}

impl<A: Archive> Members<A> {
    /// Returns the next archive member.
    ///
    /// The returned payload borrows this cursor, so the cursor cannot advance
    /// until that member is dropped or consumed.
    pub async fn next<'a>(
        &'a mut self,
    ) -> Result<Option<Member<LentPayload<'a, A::Payload<'a>>>>, A::Error> {
        Ok(self.archive.next_member().await?.map(Member::lend_payload))
    }
}

/// A one-pass archive that can enumerate and extract format-neutral members.
#[expect(
    async_fn_in_trait,
    reason = "archive readers may be !Send and run on a local executor"
)]
pub trait Archive: Sized {
    /// The archive-format error returned during member iteration.
    type Error;
    /// The streaming payload type lent by each file member.
    type Payload<'a>: MemberPayload<Error = Self::Error>
    where
        Self: 'a;

    /// Reads the next format-neutral member for [`Members::next`].
    ///
    /// Implementations must drain and validate an unfinished preceding payload
    /// before returning another member. Archive consumers should use
    /// [`Archive::members`] rather than call this hook directly: [`Members`]
    /// wraps each payload in [`LentPayload`] to enforce the lending cursor
    /// contract even when a concrete payload type does not retain its lifetime.
    async fn next_member<'a>(
        &'a mut self,
    ) -> Result<Option<Member<Self::Payload<'a>>>, Self::Error>;

    /// Consumes this archive and returns its lending member cursor.
    fn members(self) -> Members<Self> {
        Members { archive: self }
    }

    /// Securely extracts this archive beneath `destination` under `policy`.
    ///
    /// `destination` is created if it does not already exist. Symbolic links
    /// are preserved by default on platforms that support native creation;
    /// hard links require explicit opt-in through [`extract::LinkPolicy`].
    ///
    /// Archived Unix permission modes are normalized rather than restored. New
    /// regular files are created with mode `0o777` when executable intent is
    /// set and `0o666` otherwise, in both cases filtered by the process umask.
    /// Directories use the platform's default creation mode, and special mode
    /// bits are not restored. Ownership and timestamps are likewise determined
    /// by extraction activity rather than archived metadata.
    ///
    /// **IMPORTANT**: `destination` must not be concurrently modified during
    /// extraction. No correctness or isolation guarantees are made under
    /// external mutation.
    ///
    /// Extraction is streamwise: a late error can leave a partially extracted
    /// destination. Callers requiring all-or-nothing behavior should extract
    /// into a new temporary directory and atomically rename it afterward.
    async fn extract_in<P: AsRef<Path>>(
        self,
        destination: P,
        policy: extract::ExtractPolicy,
    ) -> Result<(), ExtractError<Self::Error>> {
        extract::extract(self.members(), destination.as_ref(), policy).await
    }
}

/// A valid member feature rejected by the selected [`extract::ExtractPolicy`].
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ExtractPolicyViolation {
    /// An effective member name or link target was rejected.
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
    /// A symbolic-link member requires native creation on an unsupported platform.
    #[error("native symbolic-link creation is not supported on this platform")]
    NativeSymlinkCreationUnsupported,
    /// A hard-link member appeared when links are forbidden.
    #[error("hard-link members are not allowed")]
    HardLink,
}

/// An error produced while securely extracting an archive.
#[derive(Debug, Error)]
pub enum ExtractError<E> {
    /// Reading or decoding the underlying archive failed.
    #[error(transparent)]
    Archive(E),
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
    /// An archive member path or link value is unsafe to extract.
    #[error("at byte {position}: unsafe {context} {value:?}: {reason}")]
    UnsafePath {
        /// Source member position.
        position: u64,
        /// Whether this is a member path or link target.
        context: &'static str,
        /// Archive-provided value.
        value: String,
        /// Rejection reason.
        reason: &'static str,
    },
    /// An archive entry collides with a path that cannot be replaced.
    #[error("archive entry collides with existing path {path}")]
    PathCollision {
        /// Normalized extraction-relative path.
        path: PathBuf,
    },
    /// A special member kind is deliberately excluded from extraction.
    #[error("at byte {position}: cannot extract unsupported member type {kind:?} at {path}")]
    UnsupportedMember {
        /// Source member position.
        position: u64,
        /// Normalized extraction-relative path.
        path: PathBuf,
        /// Unsupported special-file kind.
        kind: SpecialKind,
    },
    /// A symbolic or hard link cannot be safely resolved.
    #[error("at byte {position}: invalid link {path} -> {target:?}: {reason}")]
    InvalidLink {
        /// Source member position.
        position: u64,
        /// Normalized link path.
        path: PathBuf,
        /// Archive-provided or normalized link target.
        target: String,
        /// Rejection reason.
        reason: &'static str,
    },
    /// A structurally valid member was rejected by extraction policy.
    #[error("at byte {position}: extraction policy rejected input: {violation}")]
    PolicyViolation {
        /// Source member position.
        position: u64,
        /// The selected policy rule that rejected the member.
        violation: ExtractPolicyViolation,
    },
}

impl<E> ExtractError<E> {
    fn policy_violation(position: u64, violation: ExtractPolicyViolation) -> Self {
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
