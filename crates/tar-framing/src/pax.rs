//! PAX record parsing, active-global updates, and per-member metadata state.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    str::FromStr,
    sync::Arc,
};

use super::PaxKind;

const UTF8_HDRCHARSET: &str = "ISO-IR 10646 2000 UTF-8";
const BINARY_HDRCHARSET: &str = "BINARY";

/// An error encountered while parsing pax extended-header records.
#[derive(Debug, thiserror::Error)]
pub enum PaxError {
    /// A pax payload did not consist of valid extended-header records.
    #[error("invalid pax records: {reason}")]
    InvalidRecords {
        /// A concise description of the grammar violation.
        reason: &'static str,
    },
    /// A pax text component that must be UTF-8 is not valid UTF-8.
    #[error("pax records contain invalid UTF-8 text")]
    InvalidUtf8,
    /// A pax record keyword is neither standard nor an accepted namespaced extension.
    #[error("invalid or unknown pax keyword {keyword:?}")]
    InvalidKeyword {
        /// The rejected keyword.
        keyword: String,
    },
    /// A pax decimal integer field is malformed or exceeds this API's integer range.
    #[error("invalid pax {keyword} value: {value:?}")]
    InvalidInteger {
        /// The affected standard keyword.
        keyword: &'static str,
        /// The rejected textual value.
        value: String,
    },
    /// A pax file-time value is malformed or exceeds this API's integer range.
    #[error("invalid pax {keyword} time value: {value:?}")]
    InvalidTime {
        /// The affected standard keyword.
        keyword: &'static str,
        /// The rejected textual value.
        value: String,
    },
    /// A pax `hdrcharset` record requests text encoding unsupported by this API.
    #[error("unsupported pax hdrcharset value {value:?}")]
    UnsupportedCharset {
        /// The unsupported character-set identifier.
        value: String,
    },
    /// A pax record length or offset overflowed.
    #[error("arithmetic overflow while computing {context}")]
    ArithmeticOverflow {
        /// The computation that overflowed.
        context: &'static str,
    },
}

pub(crate) type SharedPaxRecords = Arc<PaxRecords>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PaxRecords(Vec<PaxRecord>);

/// An owned, hashable pax extended-header keyword.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PaxKeyword {
    /// File access time.
    Atime,
    /// Encoding of the following member's file data.
    Charset,
    /// Uninterpreted archive comment.
    Comment,
    /// File status-change time compatibility extension.
    Ctime,
    /// Numeric group identifier.
    Gid,
    /// Group name.
    Gname,
    /// Encoding of pathname and user/group-name values.
    HdrCharset,
    /// Link pathname.
    LinkPath,
    /// File modification time.
    Mtime,
    /// Member pathname.
    Path,
    /// Reserved `realtime.*` attribute.
    Realtime(Arc<str>),
    /// Reserved `security.*` attribute.
    Security(Arc<str>),
    /// Member payload size.
    Size,
    /// Numeric user identifier.
    Uid,
    /// User name.
    Uname,
    /// An implementation extension in a `vendor.keyword` namespace.
    Vendor {
        /// Vendor or organization identifier.
        vendor: Arc<str>,
        /// Keyword suffix after the vendor namespace.
        name: Arc<str>,
    },
}

impl PaxKeyword {
    pub(crate) fn components(&self) -> (&str, Option<&str>) {
        match self {
            Self::Atime => ("atime", None),
            Self::Charset => ("charset", None),
            Self::Comment => ("comment", None),
            Self::Ctime => ("ctime", None),
            Self::Gid => ("gid", None),
            Self::Gname => ("gname", None),
            Self::HdrCharset => ("hdrcharset", None),
            Self::LinkPath => ("linkpath", None),
            Self::Mtime => ("mtime", None),
            Self::Path => ("path", None),
            Self::Realtime(name) => ("realtime", Some(name)),
            Self::Security(name) => ("security", Some(name)),
            Self::Size => ("size", None),
            Self::Uid => ("uid", None),
            Self::Uname => ("uname", None),
            Self::Vendor { vendor, name } => (vendor, Some(name)),
        }
    }
}

impl fmt::Display for PaxKeyword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (namespace, name) = self.components();
        formatter.write_str(namespace)?;
        if let Some(name) = name {
            formatter.write_str(".")?;
            formatter.write_str(name)?;
        }
        Ok(())
    }
}

/// Like [`PaxRecords`], but with an additional index of `keyword -> effective record index`
/// to keep lookups cheap, even across pathological pax archives (e.g. multiple
/// global extensions being merged together).
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct GlobalPaxRecords {
    records: PaxRecords,
    indices: HashMap<PaxKeyword, usize>,
}

impl GlobalPaxRecords {
    fn apply(&mut self, updates: &PaxRecords) {
        for update in updates.as_slice() {
            match self.indices.entry(update.keyword()) {
                Entry::Occupied(entry) => self.records.0[*entry.get()] = update.clone(),
                Entry::Vacant(entry) => {
                    let index = self.records.0.len();
                    self.records.0.push(update.clone());
                    entry.insert(index);
                }
            }
        }
    }

    fn get(&self, keyword: &PaxKeyword) -> Option<&PaxRecord> {
        self.indices
            .get(keyword)
            .and_then(|index| self.records.as_slice().get(*index))
    }

    pub(super) fn hdrcharset(&self) -> HdrCharset {
        self.get(&PaxKeyword::HdrCharset)
            .and_then(|record| match record {
                PaxRecord::HdrCharset(value) => Some(value),
                _ => None,
            })
            .map_or(HdrCharset::Utf8, |value| match value {
                PaxValue::Value(value) => *value,
                PaxValue::Deleted => HdrCharset::Utf8,
            })
    }
}

/// One positioned parsed pax extended header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaxExtension {
    /// The absolute byte position of the pax extension header block.
    pub position: u64,
    /// Whether this extension has local or global scope.
    pub kind: PaxKind,
    records: SharedPaxRecords,
}

impl PaxExtension {
    pub(crate) fn new(position: u64, kind: PaxKind, records: SharedPaxRecords) -> Self {
        Self {
            position,
            kind,
            records,
        }
    }

    /// Returns the parsed pax records in archive order.
    pub fn records(&self) -> &[PaxRecord] {
        self.records.as_slice()
    }
}

/// Unified pax metadata state applicable to one ordinary member.
///
/// Effective values apply local records over the active global state using
/// standard last-record-wins and deletion semantics. [`Self::extensions`]
/// retains the positioned extension headers newly encountered for this member.
/// The effective global state is borrowed from the originating logical reader,
/// so retaining this view also prevents that reader from advancing to another
/// member whose global state could differ.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaxState<'global> {
    global_records: Option<&'global GlobalPaxRecords>,
    global_extensions: Vec<PaxExtension>,
    local_extension: Option<PaxExtension>,
}

impl<'global> PaxState<'global> {
    pub(crate) fn new(
        global_records: Option<&'global GlobalPaxRecords>,
        global_extensions: Vec<PaxExtension>,
        local_extension: Option<PaxExtension>,
    ) -> Self {
        Self {
            global_records,
            global_extensions,
            local_extension,
        }
    }

    /// Returns positioned extensions newly encountered for this member.
    ///
    /// Global extensions are yielded in source order, followed by the optional
    /// local extension.
    pub fn extensions(&self) -> impl Iterator<Item = &PaxExtension> {
        self.global_extensions
            .iter()
            .chain(self.local_extension.iter())
    }

    /// Returns the final applicable record for `keyword`, including deletions.
    pub fn effective_record(&self, keyword: &PaxKeyword) -> Option<&PaxRecord> {
        let local_records = self
            .local_extension
            .as_ref()
            .map(|extension| extension.records.as_ref());
        Self::effective_record_from(local_records, self.global_records, keyword)
    }

    pub(super) fn effective_size<'records>(
        local_records: Option<&'records PaxRecords>,
        global_records: Option<&'records GlobalPaxRecords>,
    ) -> Option<&'records PaxValue<u64>> {
        Self::effective_record_from(local_records, global_records, &PaxKeyword::Size).and_then(
            |record| match record {
                PaxRecord::Size(value) => Some(value),
                _ => None,
            },
        )
    }

    pub(super) fn effective_record_from<'records>(
        local_records: Option<&'records PaxRecords>,
        global_records: Option<&'records GlobalPaxRecords>,
        keyword: &PaxKeyword,
    ) -> Option<&'records PaxRecord> {
        local_records
            .and_then(|records| records.get(keyword))
            .or_else(|| global_records.and_then(|records| records.get(keyword)))
    }
}

/// A character encoding for PAX pathname and user/group-name values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HdrCharset {
    /// UTF-8 extended-header text.
    Utf8,
    /// Unencoded bytes copied from the originating system.
    Binary,
}

impl FromStr for HdrCharset {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            UTF8_HDRCHARSET => Ok(Self::Utf8),
            BINARY_HDRCHARSET => Ok(Self::Binary),
            _ => Err(value.to_owned()),
        }
    }
}

/// A character value governed by the effective PAX [`HdrCharset`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaxString {
    /// A value declared or defaulted to UTF-8.
    Utf8(Arc<str>),
    /// A value declared as unencoded binary bytes.
    Binary(Arc<[u8]>),
}

/// A parsed pax value, including an explicit deletion tombstone.
///
/// Deletion tombstones are needed because pax has special semantics for
/// empty (i.e. deleted) pax records: they're considered to delete
/// "any header block field, previously entered extended header value, or global
/// extended header value of the same name."
///
/// This is a distinct state from "missing," which allows for fallbacks to
/// e.g. global pax headers or the equivalent ustar field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaxValue<T> {
    /// This record sets or overrides the attribute.
    Value(T),
    /// This record deletes the attribute from its applicable scope.
    Deleted,
}

impl<T: FromStr> FromStr for PaxValue<T> {
    type Err = T::Err;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            Ok(Self::Deleted)
        } else {
            value.parse().map(Self::Value)
        }
    }
}

impl<T> PaxValue<T> {
    fn parse_utf8(value: &[u8]) -> Result<&str, PaxError> {
        std::str::from_utf8(value).map_err(|_| PaxError::InvalidUtf8)
    }
}

/// A parsed pax extended-header record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaxRecord {
    /// File access time in integral seconds; fractional seconds are discarded.
    Atime(PaxValue<u64>),
    /// Encoding of the following member's file data.
    // TODO: Consider enforcing known values here, similarly to what we do for `hdrcharset`.
    Charset(PaxValue<Arc<str>>),
    /// An uninterpreted archive comment.
    Comment(PaxValue<Arc<str>>),
    /// File status-change time compatibility extension in integral seconds.
    ///
    /// NOTE: newer versions of the pax spec don't include this record.
    /// We support it for backwards compatibility.
    ///
    /// See: <https://www.opengroup.org/austin/aardvark/finaltext/xcubug.txt>
    /// See: <https://www.opengroup.org/austin/docs/austin_166.txt>
    /// See: <https://www.opengroup.org/austin/docs/austin_206.txt>
    Ctime(PaxValue<u64>),
    /// Numeric group identifier.
    Gid(PaxValue<u64>),
    /// Group name encoded according to the effective [`HdrCharset`].
    Gname(PaxValue<PaxString>),
    /// Encoding of pathname and user/group-name extended-header values.
    HdrCharset(PaxValue<HdrCharset>),
    /// Link pathname encoded according to the effective [`HdrCharset`].
    LinkPath(PaxValue<PaxString>),
    /// File modification time in integral seconds; fractional seconds are discarded.
    Mtime(PaxValue<u64>),
    /// Member pathname encoded according to the effective [`HdrCharset`].
    Path(PaxValue<PaxString>),
    /// A reserved `realtime.*` extended attribute.
    Realtime {
        /// Keyword suffix after `realtime.`.
        name: Arc<str>,
        /// Attribute value or deletion tombstone.
        value: PaxValue<Arc<str>>,
    },
    /// A reserved `security.*` extended attribute.
    Security {
        /// Keyword suffix after `security.`.
        name: Arc<str>,
        /// Attribute value or deletion tombstone.
        value: PaxValue<Arc<str>>,
    },
    /// Member payload size in octets.
    Size(PaxValue<u64>),
    /// Numeric user identifier.
    Uid(PaxValue<u64>),
    /// User name encoded according to the effective [`HdrCharset`].
    Uname(PaxValue<PaxString>),
    /// An implementation extension in a `vendor.keyword` namespace.
    Vendor {
        /// Vendor or organization identifier.
        vendor: Arc<str>,
        /// Keyword suffix after the vendor namespace.
        name: Arc<str>,
        /// Attribute value or deletion tombstone.
        value: PaxValue<Arc<str>>,
    },
}

impl PaxRecord {
    /// Returns this record's typed pax keyword.
    pub fn keyword(&self) -> PaxKeyword {
        match self {
            Self::Atime(_) => PaxKeyword::Atime,
            Self::Charset(_) => PaxKeyword::Charset,
            Self::Comment(_) => PaxKeyword::Comment,
            Self::Ctime(_) => PaxKeyword::Ctime,
            Self::Gid(_) => PaxKeyword::Gid,
            Self::Gname(_) => PaxKeyword::Gname,
            Self::HdrCharset(_) => PaxKeyword::HdrCharset,
            Self::LinkPath(_) => PaxKeyword::LinkPath,
            Self::Mtime(_) => PaxKeyword::Mtime,
            Self::Path(_) => PaxKeyword::Path,
            Self::Realtime { name, .. } => PaxKeyword::Realtime(Arc::clone(name)),
            Self::Security { name, .. } => PaxKeyword::Security(Arc::clone(name)),
            Self::Size(_) => PaxKeyword::Size,
            Self::Uid(_) => PaxKeyword::Uid,
            Self::Uname(_) => PaxKeyword::Uname,
            Self::Vendor { vendor, name, .. } => PaxKeyword::Vendor {
                vendor: Arc::clone(vendor),
                name: Arc::clone(name),
            },
        }
    }

    fn parse(keyword: &str, value: &[u8], hdrcharset: HdrCharset) -> Result<Self, PaxError> {
        match keyword {
            "atime" => PaxValue::parse_time("atime", value).map(Self::Atime),
            "charset" => PaxValue::parse_text(value).map(Self::Charset),
            "comment" => PaxValue::parse_text(value).map(Self::Comment),
            "ctime" => PaxValue::parse_time("ctime", value).map(Self::Ctime),
            "gid" => PaxValue::parse_integer("gid", value).map(Self::Gid),
            "gname" => PaxValue::parse_string(value, hdrcharset).map(Self::Gname),
            "hdrcharset" => PaxValue::parse_hdrcharset(value).map(Self::HdrCharset),
            "linkpath" => PaxValue::parse_string(value, hdrcharset).map(Self::LinkPath),
            "mtime" => PaxValue::parse_time("mtime", value).map(Self::Mtime),
            "path" => PaxValue::parse_string(value, hdrcharset).map(Self::Path),
            "size" => PaxValue::parse_integer("size", value).map(Self::Size),
            "uid" => PaxValue::parse_integer("uid", value).map(Self::Uid),
            "uname" => PaxValue::parse_string(value, hdrcharset).map(Self::Uname),
            _ => Self::parse_namespaced(keyword, value),
        }
    }

    fn parse_namespaced(keyword: &str, value: &[u8]) -> Result<Self, PaxError> {
        let invalid = || PaxError::InvalidKeyword {
            keyword: keyword.to_owned(),
        };
        let (namespace, name) = match keyword.split_once('.') {
            Some((namespace, name)) if !name.is_empty() => (namespace, name),
            _ => return Err(invalid()),
        };
        match namespace {
            "realtime" => Ok(Self::Realtime {
                name: Arc::from(name),
                value: PaxValue::parse_text(value)?,
            }),
            "security" => Ok(Self::Security {
                name: Arc::from(name),
                value: PaxValue::parse_text(value)?,
            }),
            vendor if !vendor.is_empty() => Ok(Self::Vendor {
                vendor: Arc::from(vendor),
                name: Arc::from(name),
                value: PaxValue::parse_text(value)?,
            }),
            _ => Err(invalid()),
        }
    }
}

impl PaxRecords {
    pub(crate) fn as_slice(&self) -> &[PaxRecord] {
        &self.0
    }

    pub(super) fn parse(
        payload: &[u8],
        inherited_hdrcharset: HdrCharset,
    ) -> Result<Self, PaxError> {
        if payload.is_empty() {
            return Err(PaxError::InvalidRecords {
                reason: "local extended header payload contains no records",
            });
        }

        let mut records = Vec::new();
        let mut cursor = 0;
        while cursor < payload.len() {
            let length_end = payload[cursor..]
                .iter()
                .position(|byte| *byte == b' ')
                .ok_or(PaxError::InvalidRecords {
                    reason: "record is missing its length separator",
                })?
                + cursor;
            if length_end == cursor {
                return Err(PaxError::InvalidRecords {
                    reason: "record length is empty",
                });
            }
            let record_len = std::str::from_utf8(&payload[cursor..length_end])
                .ok()
                .and_then(decimal_u64)
                .ok_or(PaxError::InvalidRecords {
                    reason: "record length is not a valid decimal integer",
                })?;
            let record_len =
                usize::try_from(record_len).map_err(|_| PaxError::ArithmeticOverflow {
                    context: "pax record length",
                })?;
            let record_end =
                cursor
                    .checked_add(record_len)
                    .ok_or(PaxError::ArithmeticOverflow {
                        context: "pax record end",
                    })?;
            if record_end > payload.len() {
                return Err(PaxError::InvalidRecords {
                    reason: "record length exceeds extended header payload",
                });
            }
            let record = &payload[cursor..record_end];
            if record.last() != Some(&b'\n') {
                return Err(PaxError::InvalidRecords {
                    reason: "record is not newline terminated",
                });
            }
            let content_start = length_end - cursor + 1;
            let equals = record[content_start..record.len() - 1]
                .iter()
                .position(|byte| *byte == b'=')
                .ok_or(PaxError::InvalidRecords {
                    reason: "record is missing its keyword/value separator",
                })?
                + content_start;
            if equals == content_start {
                return Err(PaxError::InvalidRecords {
                    reason: "record keyword is empty",
                });
            }
            let keyword = std::str::from_utf8(&record[content_start..equals])
                .map_err(|_| PaxError::InvalidUtf8)?;
            records.push((keyword, &record[equals + 1..record.len() - 1]));
            cursor = record_end;
        }

        // Per pax spec: the `gname`, `linkpath`, `path`, and `uname` records
        // are encoded according to `hdrcharset`, so we need to first parse
        // it (or take it from a parent global pax header) before we can parse
        // the other pax records, regardless of order.
        //
        // See: pax spec, "pax Extended Header"
        let hdrcharset = Self::resolve_hdrcharset(&records, inherited_hdrcharset)?;
        records
            .into_iter()
            .map(|(keyword, value)| PaxRecord::parse(keyword, value, hdrcharset))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    fn resolve_hdrcharset(
        records: &[(&str, &[u8])],
        inherited: HdrCharset,
    ) -> Result<HdrCharset, PaxError> {
        let mut hdrcharset = inherited;
        // TODO: Consider finding the last `hdrcharset` with a reverse search to avoid parsing
        // shadowed values here. All records would still be validated during typed parsing.
        for (keyword, value) in records {
            if *keyword == "hdrcharset" {
                hdrcharset = match PaxValue::parse_hdrcharset(value)? {
                    PaxValue::Value(value) => value,
                    PaxValue::Deleted => HdrCharset::Utf8,
                };
            }
        }
        Ok(hdrcharset)
    }

    fn get(&self, keyword: &PaxKeyword) -> Option<&PaxRecord> {
        self.0
            .iter()
            .rev()
            .find(|record| record.keyword() == *keyword)
    }

    pub(super) fn apply_global(&self, active: &mut Option<GlobalPaxRecords>) {
        active.get_or_insert_default().apply(self);
    }
}

impl PaxValue<Arc<str>> {
    fn parse_text(value: &[u8]) -> Result<Self, PaxError> {
        Self::parse_utf8(value).map(|value| match value {
            "" => Self::Deleted,
            value => Self::Value(Arc::from(value)),
        })
    }
}

impl PaxValue<PaxString> {
    /// Parses a pax "string", taking the effective [`HdrCharset`] into account.
    fn parse_string(value: &[u8], hdrcharset: HdrCharset) -> Result<Self, PaxError> {
        if value.is_empty() {
            return Ok(Self::Deleted);
        }
        match hdrcharset {
            HdrCharset::Utf8 => Self::parse_utf8(value)
                .map(Arc::from)
                .map(PaxString::Utf8)
                .map(Self::Value),
            HdrCharset::Binary => Ok(Self::Value(PaxString::Binary(Arc::from(value)))),
        }
    }
}

impl PaxValue<HdrCharset> {
    fn parse_hdrcharset(value: &[u8]) -> Result<Self, PaxError> {
        let value = Self::parse_utf8(value)?;
        value
            .parse()
            .map_err(|value| PaxError::UnsupportedCharset { value })
    }
}

impl PaxValue<u64> {
    fn parse_integer(keyword: &'static str, value: &[u8]) -> Result<Self, PaxError> {
        let value = Self::parse_utf8(value)?;
        if value.is_empty() {
            return Ok(Self::Deleted);
        }

        decimal_u64(value)
            .map(Self::Value)
            .ok_or_else(|| PaxError::InvalidInteger {
                keyword,
                value: value.to_owned(),
            })
    }

    fn parse_time(keyword: &'static str, value: &[u8]) -> Result<Self, PaxError> {
        let value = Self::parse_utf8(value)?;
        if value.is_empty() {
            return Ok(Self::Deleted);
        }

        let invalid = || PaxError::InvalidTime {
            keyword,
            value: value.to_owned(),
        };
        let seconds = match value.split_once('.') {
            Some((seconds, fractional_digits))
                if !fractional_digits.is_empty()
                    && fractional_digits.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                seconds
            }
            Some(_) => return Err(invalid()),
            None => value,
        };
        decimal_u64(seconds).map(Self::Value).ok_or_else(invalid)
    }
}

fn decimal_u64(value: &str) -> Option<u64> {
    if value.starts_with('+') {
        return None;
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::*;
    use crate::test_support::{raw_record, record};

    fn text(value: &str) -> Arc<str> {
        Arc::from(value)
    }

    fn comment(value: &str) -> PaxRecord {
        PaxRecord::Comment(PaxValue::Value(text(value)))
    }

    fn utf8(value: &str) -> PaxString {
        PaxString::Utf8(text(value))
    }

    fn binary(value: &[u8]) -> PaxString {
        PaxString::Binary(Arc::from(value))
    }

    fn vendor(name: &str, value: &str) -> PaxRecord {
        PaxRecord::Vendor {
            vendor: text("Acme"),
            name: text(name),
            value: PaxValue::Value(text(value)),
        }
    }

    fn security(value: &str) -> PaxRecord {
        PaxRecord::Security {
            name: text("label"),
            value: PaxValue::Value(text(value)),
        }
    }

    fn global_state(records: Vec<PaxRecord>) -> Option<GlobalPaxRecords> {
        let mut active = None;
        PaxRecords(records).apply_global(&mut active);
        active
    }

    fn extension(position: u64, kind: PaxKind, records: Vec<PaxRecord>) -> PaxExtension {
        PaxExtension::new(position, kind, Arc::new(PaxRecords(records)))
    }

    #[test]
    fn resolves_state_precedence_and_preserves_extension_order() {
        struct Case {
            name: &'static str,
            global: Vec<PaxRecord>,
            local: Option<Vec<PaxRecord>>,
            expected: Option<PaxRecord>,
        }

        for case in [
            Case {
                name: "missing",
                global: Vec::new(),
                local: None,
                expected: None,
            },
            Case {
                name: "global",
                global: vec![comment("global")],
                local: None,
                expected: Some(comment("global")),
            },
            Case {
                name: "local overrides global",
                global: vec![comment("global")],
                local: Some(vec![comment("local")]),
                expected: Some(comment("local")),
            },
            Case {
                name: "last local duplicate wins",
                global: Vec::new(),
                local: Some(vec![comment("first"), comment("last")]),
                expected: Some(comment("last")),
            },
            Case {
                name: "local deletion suppresses global",
                global: vec![comment("global")],
                local: Some(vec![PaxRecord::Comment(PaxValue::Deleted)]),
                expected: Some(PaxRecord::Comment(PaxValue::Deleted)),
            },
        ] {
            let global = global_state(case.global);
            let state = PaxState::new(
                global.as_ref(),
                Vec::new(),
                case.local
                    .map(|records| extension(0, PaxKind::Local, records)),
            );
            assert_eq!(
                state.effective_record(&PaxKeyword::Comment),
                case.expected.as_ref(),
                "{}",
                case.name
            );
        }

        let state = PaxState::new(
            None,
            vec![
                extension(3, PaxKind::Global, vec![vendor("first", "value")]),
                extension(7, PaxKind::Global, vec![vendor("second", "value")]),
            ],
            Some(extension(
                11,
                PaxKind::Local,
                vec![vendor("local", "value")],
            )),
        );
        assert_eq!(
            state
                .extensions()
                .map(|extension| (extension.position, extension.kind))
                .collect::<Vec<_>>(),
            [
                (3, PaxKind::Global),
                (7, PaxKind::Global),
                (11, PaxKind::Local),
            ]
        );
    }

    #[test]
    fn updates_effective_global_state_in_place() {
        let physical_records = Arc::new(PaxRecords(vec![comment("initial")]));
        let mut active = None;
        physical_records.apply_global(&mut active);
        let initial_state = ptr::from_ref(active.as_ref().expect("global state should exist"));

        PaxRecords(vec![vendor("attribute", "value")]).apply_global(&mut active);

        assert_eq!(
            ptr::from_ref(active.as_ref().expect("global state should exist")),
            initial_state
        );
        assert_eq!(physical_records.as_slice(), [comment("initial")]);
    }

    #[test]
    fn global_deletions_remain_effective_tombstones() {
        let initial = Arc::new(PaxRecords(vec![
            PaxRecord::Path(PaxValue::Value(utf8("global"))),
            vendor("kept", "value"),
        ]));
        let deletion = Arc::new(PaxRecords(vec![PaxRecord::Path(PaxValue::Deleted)]));
        let mut active = None;
        initial.apply_global(&mut active);
        deletion.apply_global(&mut active);

        let active_records = active.as_ref().expect("global state should exist");
        assert_eq!(active_records.records.as_slice().len(), 2);
        let state = PaxState::new(active.as_ref(), Vec::new(), None);
        assert_eq!(
            state.effective_record(&PaxKeyword::Path),
            Some(&PaxRecord::Path(PaxValue::Deleted))
        );
    }

    #[test]
    fn parses_values_and_deletions_through_from_str() {
        assert!(matches!(
            "".parse::<PaxValue<String>>(),
            Ok(PaxValue::Deleted)
        ));
        assert!(matches!(
            "value".parse::<PaxValue<String>>(),
            Ok(PaxValue::Value(value)) if value == "value"
        ));
        assert!(matches!(
            "12".parse::<PaxValue<u64>>(),
            Ok(PaxValue::Value(12))
        ));
    }

    #[test]
    fn parses_strict_numeric_and_timestamp_values() {
        assert!(matches!(
            PaxValue::parse_integer("uid", b"12"),
            Ok(PaxValue::Value(12))
        ));
        assert!(matches!(
            PaxValue::parse_integer("uid", b""),
            Ok(PaxValue::Deleted)
        ));
        assert!(matches!(
            PaxValue::parse_time("mtime", b"12.034"),
            Ok(PaxValue::Value(12))
        ));
        assert!(matches!(
            PaxValue::parse_time("mtime", b""),
            Ok(PaxValue::Deleted)
        ));

        for value in ["+1", "-1", "12x", "18446744073709551616"] {
            assert!(matches!(
                PaxValue::parse_integer("gid", value.as_bytes()),
                Err(PaxError::InvalidInteger { .. })
            ));
        }
        for value in ["+1", "-1", "1.", "1.nanosecond", "18446744073709551616"] {
            assert!(matches!(
                PaxValue::parse_time("atime", value.as_bytes()),
                Err(PaxError::InvalidTime { .. })
            ));
        }
    }

    #[test]
    fn parses_typed_standard_reserved_and_vendor_records() {
        let fields = [
            ("atime", "12.034"),
            ("charset", "BINARY"),
            ("comment", "a=b"),
            ("ctime", "17.500"),
            ("gid", "7"),
            ("gname", "group"),
            ("hdrcharset", UTF8_HDRCHARSET),
            ("linkpath", "target"),
            ("mtime", "42"),
            ("path", "file"),
            ("realtime.deadline", "soon"),
            ("security.label", "secure"),
            ("size", "0"),
            ("uid", "8"),
            ("uname", "user"),
            ("Acme.attribute", "custom"),
        ];
        let mut payload = Vec::new();
        for (keyword, value) in fields {
            payload.extend_from_slice(&record(keyword, value));
        }

        let Ok(records) = PaxRecords::parse(&payload, HdrCharset::Utf8) else {
            panic!("records should parse");
        };
        assert_eq!(
            records.as_slice(),
            [
                PaxRecord::Atime(PaxValue::Value(12)),
                PaxRecord::Charset(PaxValue::Value(text("BINARY"))),
                comment("a=b"),
                PaxRecord::Ctime(PaxValue::Value(17)),
                PaxRecord::Gid(PaxValue::Value(7)),
                PaxRecord::Gname(PaxValue::Value(utf8("group"))),
                PaxRecord::HdrCharset(PaxValue::Value(HdrCharset::Utf8)),
                PaxRecord::LinkPath(PaxValue::Value(utf8("target"))),
                PaxRecord::Mtime(PaxValue::Value(42)),
                PaxRecord::Path(PaxValue::Value(utf8("file"))),
                PaxRecord::Realtime {
                    name: text("deadline"),
                    value: PaxValue::Value(text("soon")),
                },
                security("secure"),
                PaxRecord::Size(PaxValue::Value(0)),
                PaxRecord::Uid(PaxValue::Value(8)),
                PaxRecord::Uname(PaxValue::Value(utf8("user"))),
                vendor("attribute", "custom"),
            ]
        );
        assert!(
            records
                .as_slice()
                .iter()
                .zip(fields)
                .all(|(record, (keyword, _))| record.keyword().to_string() == keyword)
        );
    }

    #[test]
    fn parses_deleted_ctime_compatibility_extension() {
        let Ok(records) = PaxRecords::parse(&record("ctime", ""), HdrCharset::Utf8) else {
            panic!("ctime deletion should parse");
        };
        assert_eq!(records.as_slice(), [PaxRecord::Ctime(PaxValue::Deleted)]);
    }

    #[test]
    fn rejects_invalid_records_and_keywords() {
        for payload in [
            b"11 path=name".as_slice(),
            b"12 pathname\n".as_slice(),
            b"99 path=name\n".as_slice(),
            b"+12 path=name\n".as_slice(),
        ] {
            assert!(matches!(
                PaxRecords::parse(payload, HdrCharset::Utf8),
                Err(PaxError::InvalidRecords { .. })
            ));
        }

        let invalid_utf8 = raw_record(b"path", &[0xff]);
        assert!(matches!(
            PaxRecords::parse(&invalid_utf8, HdrCharset::Utf8),
            Err(PaxError::InvalidUtf8)
        ));

        for keyword in ["unknown", "VENDOR", "VENDOR.", "realtime.", "security."] {
            assert!(matches!(
                PaxRecord::parse(keyword, b"value", HdrCharset::Utf8),
                Err(PaxError::InvalidKeyword { .. })
            ));
        }
    }

    #[test]
    fn applies_namespaced_globals_and_accepts_supported_hdrcharset_records() {
        let mut active = global_state(vec![
            vendor("first", "old"),
            vendor("second", "kept"),
            security("old"),
        ]);
        let update = Arc::new(PaxRecords(vec![vendor("first", "new"), security("new")]));
        update.apply_global(&mut active);
        let active = active.as_ref().expect("global state should exist");
        assert_eq!(active.records.as_slice().len(), 3);
        assert_eq!(
            active.get(&PaxKeyword::Vendor {
                vendor: text("Acme"),
                name: text("first"),
            }),
            Some(&vendor("first", "new"))
        );
        assert_eq!(
            active.get(&PaxKeyword::Security(text("label"))),
            Some(&security("new"))
        );

        for (case, payload) in [
            (
                "supported hdrcharset",
                record("hdrcharset", UTF8_HDRCHARSET),
            ),
            ("deleted hdrcharset", record("hdrcharset", "")),
            ("member data charset", record("charset", "BINARY")),
        ] {
            assert!(
                PaxRecords::parse(&payload, HdrCharset::Utf8).is_ok(),
                "{case}"
            );
        }

        let mut binary_values = record("hdrcharset", BINARY_HDRCHARSET);
        for (keyword, value) in [
            (b"gname".as_slice(), [0xfc]),
            (b"linkpath".as_slice(), [0xfd]),
            (b"path".as_slice(), [0xfe]),
            (b"uname".as_slice(), [0xff]),
        ] {
            binary_values.extend_from_slice(&raw_record(keyword, &value));
        }
        let Ok(binary_records) = PaxRecords::parse(&binary_values, HdrCharset::Utf8) else {
            panic!("binary records should parse");
        };
        assert_eq!(
            binary_records.as_slice(),
            [
                PaxRecord::HdrCharset(PaxValue::Value(HdrCharset::Binary)),
                PaxRecord::Gname(PaxValue::Value(binary(&[0xfc]))),
                PaxRecord::LinkPath(PaxValue::Value(binary(&[0xfd]))),
                PaxRecord::Path(PaxValue::Value(binary(&[0xfe]))),
                PaxRecord::Uname(PaxValue::Value(binary(&[0xff]))),
            ]
        );
        let inherited_binary_path = raw_record(b"path", &[0xfe]);
        let Ok(inherited_records) = PaxRecords::parse(&inherited_binary_path, HdrCharset::Binary)
        else {
            panic!("inherited binary records should parse");
        };
        assert_eq!(
            inherited_records.as_slice(),
            [PaxRecord::Path(PaxValue::Value(binary(&[0xfe])))]
        );
        let mut reset_to_utf8 = record("hdrcharset", "");
        reset_to_utf8.extend_from_slice(&raw_record(b"path", &[0xfd]));
        assert!(matches!(
            PaxRecords::parse(&reset_to_utf8, HdrCharset::Binary),
            Err(PaxError::InvalidUtf8)
        ));
        let mut binary_comment = record("hdrcharset", BINARY_HDRCHARSET);
        binary_comment.extend_from_slice(&raw_record(b"comment", &[0xff]));
        assert!(matches!(
            PaxRecords::parse(&binary_comment, HdrCharset::Utf8),
            Err(PaxError::InvalidUtf8)
        ));

        let unsupported_value = "ISO-IR 8859 1 1998";
        let mut overridden_unsupported = record("hdrcharset", unsupported_value);
        overridden_unsupported.extend_from_slice(&record("hdrcharset", UTF8_HDRCHARSET));
        for unsupported in [
            record("hdrcharset", unsupported_value),
            overridden_unsupported,
        ] {
            assert!(matches!(
                PaxRecords::parse(&unsupported, HdrCharset::Utf8),
                Err(PaxError::UnsupportedCharset { .. })
            ));
        }
    }
}
