//! Member-oriented decoding of pax or GNU tar streams.

use std::collections::HashSet;

use archive_trait::{
    Archive as ArchiveTrait, Member, MemberMetadata, MemberPayload as MemberPayloadTrait,
    SpecialKind,
};
use tar_framing::{
    ArchiveFormat, FrameError, PaxKeyword, PaxKind, PaxRecord, PaxValue, UstarKind,
    logical::{MemberExtensions, MemberFrame, MemberPayload as FramingMemberPayload, TarReader},
};
use thiserror::Error;
use tokio::io::AsyncRead;

pub use tar_framing::{
    DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE, DEFAULT_MAX_GNU_EXTENSION_SIZE,
    DEFAULT_MAX_PAX_EXTENSION_SIZE,
};

/// A one-pass reader for a validated pax or GNU tar archive.
///
/// Member iteration is fused. After reaching the end of the archive or
/// returning a decoding error, every subsequent attempt returns end-of-archive.
pub struct TarArchive<R> {
    reader: TarReader<R>,
    policy: DecodePolicy,
    fused: bool,
}

impl<R> TarArchive<R> {
    /// Creates an archive decoder from an uncompressed tar reader.
    pub fn new(reader: R) -> Self {
        Self::new_with_policy(reader, DecodePolicy::default())
    }

    /// Creates an archive decoder using `policy`.
    pub fn new_with_policy(reader: R, policy: DecodePolicy) -> Self {
        let mut reader = TarReader::new(reader);
        reader.set_max_pax_extension_size(policy.pax_policy.max_extension_size);
        reader.set_max_global_pax_extensions_size(policy.pax_policy.max_global_extensions_size);
        reader.set_allow_all_nul_numeric_fields(policy.allow_all_nul_numeric_fields);
        reader.set_max_gnu_extension_size(policy.max_gnu_extension_size);
        Self {
            reader,
            policy,
            fused: false,
        }
    }
}

/// Controls tar compatibility and the feature subset member decoding may accept.
///
/// See each configuration API for its default.
#[derive(Clone, Copy, Debug)]
pub struct DecodePolicy {
    allow_gnu: bool,
    allow_all_nul_numeric_fields: bool,
    max_gnu_extension_size: u64,
    pax_policy: PaxDecodePolicy,
}

/// Controls pax compatibility and the feature subset member decoding may accept.
///
/// See each allow API for its default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PaxDecodePolicy {
    max_extension_size: u64,
    max_global_extensions_size: u64,
    allow_non_utf8_pax_vendor_values: bool,
    allow_global_pax_extensions: bool,
    allow_unknown_pax_vendor_records: bool,
    allow_duplicate_pax_records: bool,
    allow_global_pax_member_metadata: bool,
}

impl Default for PaxDecodePolicy {
    fn default() -> Self {
        Self {
            max_extension_size: DEFAULT_MAX_PAX_EXTENSION_SIZE,
            max_global_extensions_size: DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE,
            allow_non_utf8_pax_vendor_values: true,
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
            allow_gnu: true,
            allow_all_nul_numeric_fields: true,
            max_gnu_extension_size: DEFAULT_MAX_GNU_EXTENSION_SIZE,
            pax_policy: PaxDecodePolicy::default(),
        }
    }
}

impl DecodePolicy {
    /// Configures whether archives in the GNU framing family may be decoded.
    ///
    /// GNU tar archives are **allowed by default**.
    ///
    /// Users who wish to parse strictly pax-confirming tar archives may wish to
    /// disable this setting.
    pub fn allow_gnu(mut self, allow: bool) -> Self {
        self.allow_gnu = allow;
        self
    }

    /// Configures whether wholly NUL numeric metadata fields may be accepted.
    ///
    /// This compatibility option applies to the ordinary header's `mode`, `uid`,
    /// `gid`, and `mtime` fields in both pax/ustar and GNU archives. It is
    /// **enabled by default**. When enabled, a wholly NUL field is represented
    /// as missing; every other value must be a valid numeric encoding for its
    /// archive family.
    pub fn allow_all_nul_numeric_fields(mut self, allow: bool) -> Self {
        self.allow_all_nul_numeric_fields = allow;
        self
    }

    /// Configures the maximum payload size accepted for one GNU metadata extension.
    ///
    /// The limit applies independently to long-name and long-link extensions.
    /// An extension that declares a larger payload is rejected before its
    /// payload is consumed. The default is [`DEFAULT_MAX_GNU_EXTENSION_SIZE`].
    /// Setting the limit to zero rejects every nonempty GNU extension. Setting
    /// it to [`u64::MAX`] permits unbounded metadata buffering.
    pub fn max_gnu_extension_size(mut self, max_gnu_extension_size: u64) -> Self {
        self.max_gnu_extension_size = max_gnu_extension_size;
        self
    }

    /// Configures the accepted pax feature subset.
    pub fn pax_policy(mut self, policy: PaxDecodePolicy) -> Self {
        self.pax_policy = policy;
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
}

impl PaxDecodePolicy {
    /// Configures the maximum payload size in bytes accepted for one pax extension.
    ///
    /// The limit applies independently to each local or global extension and
    /// covers all records in that extension. An extension that declares a
    /// larger payload is rejected before its payload is consumed.
    ///
    /// The default is [`DEFAULT_MAX_PAX_EXTENSION_SIZE`]. Setting the limit to
    /// zero rejects every nonempty pax extension. Setting it to [`u64::MAX`]
    /// removes the per-extension bound; global extensions remain subject to
    /// their cumulative limit.
    pub fn max_extension_size(mut self, max_extension_size: u64) -> Self {
        self.max_extension_size = max_extension_size;
        self
    }

    /// Configures the maximum cumulative payload size of global pax extensions.
    ///
    /// The total is reset after each ordinary member. A global extension that
    /// would increase the pending total beyond this limit is rejected before
    /// its payload is consumed. The default is
    /// [`DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE`]. Setting the limit to zero
    /// rejects every nonempty global extension. Setting it to [`u64::MAX`]
    /// removes the cumulative bound; each extension remains subject to its
    /// individual limit.
    pub fn max_global_extensions_size(mut self, max_global_extensions_size: u64) -> Self {
        self.max_global_extensions_size = max_global_extensions_size;
        self
    }

    /// Configures whether vendor-namespaced pax record values may contain non-UTF-8 bytes.
    ///
    /// This compatibility option is enabled by default to accommodate raw extensions
    /// incorrectly emitted by other real-world writers. Disabling it requires every vendor
    /// record value to be valid UTF-8. Vendor values remain exposed as opaque
    /// bytes in either mode.
    ///
    /// [`Self::allow_unknown_pax_vendor_records`] separately controls whether
    /// decoding may ignore vendor records after they have been parsed.
    pub fn allow_non_utf8_pax_vendor_values(mut self, allow: bool) -> Self {
        self.allow_non_utf8_pax_vendor_values = allow;
        self
    }

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
    /// decoding error. Their values are parsed structurally, but their semantics
    /// are not interpreted.
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
        for record in records {
            if let PaxRecord::Vendor {
                vendor,
                name,
                value,
            } = record
            {
                if !self.allow_unknown_pax_vendor_records {
                    return Err(DecodeError::policy_violation(
                        position,
                        DecodePolicyViolation::PaxVendorExtension {
                            vendor: vendor.to_string(),
                            name: name.to_string(),
                        },
                    ));
                }

                if !self.allow_non_utf8_pax_vendor_values
                    && let PaxValue::Value(value) = value
                    && std::str::from_utf8(value).is_err()
                {
                    return Err(DecodeError::policy_violation(
                        position,
                        DecodePolicyViolation::NonUtf8PaxVendorValue {
                            vendor: vendor.to_string(),
                            name: name.to_string(),
                        },
                    ));
                }
            }
        }

        if kind == PaxKind::Global && !self.allow_global_pax_member_metadata {
            for record in records {
                let keyword = match record.keyword() {
                    PaxKeyword::Path => Some("path"),
                    PaxKeyword::LinkPath => Some("linkpath"),
                    PaxKeyword::Size => Some("size"),
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
                let keyword = record.keyword();
                if !keywords.insert(keyword.clone()) {
                    return Err(DecodeError::policy_violation(
                        position,
                        DecodePolicyViolation::DuplicatePaxRecord {
                            keyword: keyword.to_string(),
                        },
                    ));
                }
            }
        }

        Ok(())
    }
}

/// A tar feature accepted by framing but rejected by the selected [`DecodePolicy`].
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DecodePolicyViolation {
    /// A GNU-family frame appeared when only POSIX-pax decoding is allowed.
    #[error("GNU archives are not allowed")]
    GnuArchive,
    /// A global POSIX pax extended header appeared when it is forbidden.
    #[error("global pax extended headers are not allowed")]
    GlobalPaxExtension,
    /// A vendor-namespaced POSIX pax record appeared.
    #[error("pax vendor extension {vendor}.{name} is not allowed")]
    PaxVendorExtension {
        /// Vendor namespace.
        vendor: String,
        /// Keyword suffix following the vendor namespace.
        name: String,
    },
    /// A vendor-namespaced POSIX pax record contains a non-UTF-8 value.
    #[error("pax vendor extension {vendor}.{name} contains a non-UTF-8 value")]
    NonUtf8PaxVendorValue {
        /// Vendor namespace.
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

/// An error produced while decoding tar members.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// The underlying tar stream is not structurally valid.
    #[error(transparent)]
    Framing(#[from] FrameError),
    /// An effective member path or link target is not UTF-8 text.
    #[error("at byte {position}: {field} is not valid UTF-8")]
    InvalidUtf8 {
        /// Source tar block position.
        position: u64,
        /// Metadata field being decoded.
        field: &'static str,
    },
    /// A structurally valid tar feature was rejected by decode policy.
    #[error("at byte {position}: decode policy rejected input: {violation}")]
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
}

/// A tar member payload adapted to [`MemberPayloadTrait`].
pub struct TarMemberPayload<'a, R> {
    payload: FramingMemberPayload<'a, R>,
}

impl<R: AsyncRead + Unpin> MemberPayloadTrait for TarMemberPayload<'_, R> {
    type Error = DecodeError;

    async fn next_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, Self::Error> {
        self.payload
            .next_chunk(buffer, target_len)
            .await
            .map_err(Into::into)
    }

    async fn skip(self) -> Result<(), Self::Error> {
        self.payload.skip().await.map_err(Into::into)
    }
}

impl<R: AsyncRead + Unpin> ArchiveTrait for TarArchive<R> {
    type Error = DecodeError;
    type Payload<'a>
        = TarMemberPayload<'a, R>
    where
        Self: 'a;

    async fn next_member<'a>(
        &'a mut self,
    ) -> Result<Option<Member<Self::Payload<'a>>>, Self::Error> {
        if self.fused {
            return Ok(None);
        }
        let frame = match self.reader.next_frame().await {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                self.fused = true;
                return Ok(None);
            }
            Err(error) => {
                self.fused = true;
                return Err(error.into());
            }
        };
        if let Err(error) = self.policy.check_member(&frame) {
            self.fused = true;
            return Err(error);
        }
        match project_member(frame) {
            Ok(member) => Ok(Some(member)),
            Err(error) => {
                self.fused = true;
                Err(error)
            }
        }
    }
}

fn project_member<'a, R>(
    frame: MemberFrame<'a, R>,
) -> Result<Member<TarMemberPayload<'a, R>>, DecodeError> {
    let position = frame.header.position;
    let kind = frame.header.kind;
    let size = frame.header.effective_size;
    let executable = frame.header.mode.unwrap_or_default() & 0o111 != 0;
    let path = std::str::from_utf8(frame.effective_path()?.as_ref())
        .map(str::to_owned)
        .map_err(|_| DecodeError::InvalidUtf8 {
            position,
            field: "path",
        })?;
    let target = if matches!(kind, UstarKind::HardLink | UstarKind::SymbolicLink) {
        std::str::from_utf8(frame.effective_link_path()?.as_ref())
            .map(str::to_owned)
            .map_err(|_| DecodeError::InvalidUtf8 {
                position,
                field: "linkpath",
            })?
    } else {
        String::new()
    };
    let metadata = MemberMetadata { path, position };

    Ok(match kind {
        UstarKind::Regular | UstarKind::Contiguous => Member::File {
            metadata,
            size,
            executable,
            payload: TarMemberPayload {
                payload: frame.payload,
            },
        },
        UstarKind::Directory => Member::Directory { metadata },
        UstarKind::SymbolicLink => Member::SymbolicLink { metadata, target },
        UstarKind::HardLink => Member::HardLink {
            metadata,
            target,
            size,
            payload: TarMemberPayload {
                payload: frame.payload,
            },
        },
        UstarKind::CharacterDevice => Member::Special {
            metadata,
            kind: SpecialKind::CharacterDevice,
        },
        UstarKind::BlockDevice => Member::Special {
            metadata,
            kind: SpecialKind::BlockDevice,
        },
        UstarKind::Fifo => Member::Special {
            metadata,
            kind: SpecialKind::Fifo,
        },
    })
}
