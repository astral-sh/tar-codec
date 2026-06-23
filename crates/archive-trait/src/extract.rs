//! Format-neutral archive extraction.
//!
//! [`ExtractPolicy`] configures common path, overwrite, and link behavior.
//! Filesystem mutation is capability-relative and confined to the destination.

mod path;
mod root;

use std::path::Path;

use self::{path::decode_member, root::ExtractionRoot};
use super::*;

/// Controls behavior shared by [`Archive::extract_in`] implementations.
///
/// See each configuration API for its default.
#[derive(Clone, Copy, Debug)]
pub struct ExtractPolicy {
    pub(crate) link_policy: LinkPolicy,
    pub(crate) allow_overwrites: bool,
    pub(crate) name_validation: crate::name::NameValidation,
}

/// Controls how symbolic- and hard-link members are extracted.
///
/// By default, symbolic links are preserved as native links, including links
/// to missing targets. Hard links and ambient symbolic-link targets require
/// explicit opt-in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkPolicy {
    pub(crate) symlink_policy: SymlinkPolicy,
    pub(crate) allow_hard_links: bool,
    pub(crate) allow_ambient_targets: bool,
    pub(crate) allow_missing_targets: bool,
}

/// Controls how symbolic-link members are handled during extraction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SymlinkPolicy {
    /// Preserve symbolic-link members as native filesystem links.
    #[default]
    Preserve,
    /// Ignore symbolic-link members without changing the filesystem.
    Skip,
    /// Reject archives containing symbolic-link members.
    Reject,
}

impl Default for ExtractPolicy {
    fn default() -> Self {
        Self {
            link_policy: LinkPolicy::default(),
            allow_overwrites: true,
            name_validation: crate::name::NameValidation::Default,
        }
    }
}

impl Default for LinkPolicy {
    fn default() -> Self {
        Self {
            symlink_policy: SymlinkPolicy::default(),
            allow_hard_links: false,
            allow_ambient_targets: false,
            allow_missing_targets: true,
        }
    }
}

impl ExtractPolicy {
    /// Configures symbolic- and hard-link extraction behavior.
    pub fn link_policy(mut self, policy: LinkPolicy) -> Self {
        self.link_policy = policy;
        self
    }

    /// Configures whether archive members may replace existing entries.
    ///
    /// Overwrites are **allowed by default**. Replacement never follows
    /// symbolic links or recursively removes non-empty directories. Real
    /// directories are always reused, including when overwrites are disabled.
    pub fn allow_overwrites(mut self, allow: bool) -> Self {
        self.allow_overwrites = allow;
        self
    }

    /// Configures validation for member names and link targets.
    ///
    /// Passing [`None`] disables configurable name validation. UTF-8 and
    /// extraction containment requirements still apply.
    pub fn name_validator(mut self, validator: Option<NameValidator>) -> Self {
        self.name_validation = crate::name::NameValidation::from_validator(validator);
        self
    }

    fn check_name<E>(
        self,
        position: u64,
        context: &'static str,
        value: &str,
    ) -> Result<(), ExtractError<E>> {
        if !self.name_validation.accepts(value) {
            return Err(ExtractError::policy_violation(
                position,
                ExtractPolicyViolation::NameRejected {
                    context,
                    value: value.to_owned(),
                },
            ));
        }
        Ok(())
    }
}

impl LinkPolicy {
    /// Configures how symbolic-link members are handled during extraction.
    ///
    /// Symbolic links are preserved by default. Platforms without native
    /// symbolic-link creation require [`SymlinkPolicy::Skip`] or
    /// [`SymlinkPolicy::Reject`].
    pub fn symlink_policy(mut self, policy: SymlinkPolicy) -> Self {
        self.symlink_policy = policy;
        self
    }

    /// Configures whether hard-link members may be extracted.
    ///
    /// Hard links are **forbidden by default** because they are uncommon,
    /// difficult to extract consistently, and prone to implementation
    /// differentials. Enable them only for trusted archives.
    pub fn allow_hard_links(mut self, allow: bool) -> Self {
        self.allow_hard_links = allow;
        self
    }

    /// Configures whether pre-existing symbolic-link targets may be used.
    ///
    /// Existing symbolic links are followed only when capability-relative
    /// resolution remains beneath the extraction root. Ambient targets are
    /// **forbidden by default**. This does not affect hard-link validation.
    pub fn allow_ambient_targets(mut self, allow: bool) -> Self {
        self.allow_ambient_targets = allow;
        self
    }

    /// Configures whether symbolic links to missing targets may be extracted.
    ///
    /// Missing symbolic-link targets are **allowed by default**. This does not
    /// affect hard-link validation.
    pub fn allow_missing_targets(mut self, allow: bool) -> Self {
        self.allow_missing_targets = allow;
        self
    }
}

/// Extracts a member stream into `destination` under the shared extraction policy.
pub(crate) async fn extract<A: Archive>(
    mut members: Members<A>,
    destination: &Path,
    policy: ExtractPolicy,
) -> Result<(), ExtractError<A::Error>> {
    let mut root = ExtractionRoot::<A::Error>::open(destination, policy.allow_overwrites).await?;
    // Scratch space reused for each payload read and streamed directly for large files.
    let mut chunk_buffer = Vec::new();
    // Complete small-file contents, buffered so payload validation precedes file creation.
    let mut buffered_payload = Vec::new();
    let result: Result<(), ExtractError<A::Error>> = async {
        while let Some(member) = members.next().await.map_err(ExtractError::Archive)? {
            check_member_policy(&member, policy)?;
            let decoded = decode_member(&member, policy)?;
            match member {
                Member::File {
                    size,
                    executable,
                    payload,
                    ..
                } => {
                    root.extract_file(
                        &decoded.path,
                        size,
                        executable,
                        payload,
                        &mut chunk_buffer,
                        &mut buffered_payload,
                    )
                    .await?;
                }
                Member::Directory { .. } => root.extract_directory(&decoded.path).await?,
                Member::SymbolicLink { .. } => {
                    if policy.link_policy.symlink_policy == SymlinkPolicy::Preserve {
                        root.reserve_symlink(&decoded).await?;
                    }
                }
                Member::HardLink { size, payload, .. } => {
                    root.extract_hard_link(&decoded, size, payload, &mut chunk_buffer)
                        .await?;
                }
                Member::Special { kind, .. } => {
                    return Err(ExtractError::UnsupportedMember {
                        position: decoded.position,
                        path: decoded.path.to_path_buf(),
                        kind,
                    });
                }
            }
        }
        Ok(())
    }
    .await;
    // Commit earlier validated files before reporting a later member error.
    root.flush_buffered_files().await?;
    result?;
    root.finalize_symlinks(policy.link_policy).await
}

fn check_member_policy<E, P>(
    member: &Member<P>,
    policy: ExtractPolicy,
) -> Result<(), ExtractError<E>> {
    let position = member.metadata().position;
    match member {
        Member::SymbolicLink { .. } => {
            let violation = match policy.link_policy.symlink_policy {
                SymlinkPolicy::Reject => Some(ExtractPolicyViolation::SymbolicLink),
                #[cfg(not(unix))]
                SymlinkPolicy::Preserve => {
                    Some(ExtractPolicyViolation::NativeSymlinkCreationUnsupported)
                }
                _ => None,
            };
            if let Some(violation) = violation {
                return Err(ExtractError::policy_violation(position, violation));
            }
        }
        Member::HardLink { .. } if !policy.link_policy.allow_hard_links => {
            return Err(ExtractError::policy_violation(
                position,
                ExtractPolicyViolation::HardLink,
            ));
        }
        _ => {}
    }
    Ok(())
}
