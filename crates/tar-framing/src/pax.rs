use std::{borrow::Cow, str::FromStr};

use super::{FrameError, FrameErrorInner};

const UTF8_HDRCHARSET: &str = "ISO-IR 10646 2000 UTF-8";
const BINARY_HDRCHARSET: &str = "BINARY";

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
    Utf8(String),
    /// A value declared as unencoded binary bytes.
    Binary(Vec<u8>),
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

/// A parsed pax extended-header record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaxRecord {
    /// File access time in integral seconds; fractional seconds are discarded.
    Atime(PaxValue<u64>),
    /// Encoding of the following member's file data.
    Charset(PaxValue<String>),
    /// An uninterpreted archive comment.
    Comment(PaxValue<String>),
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
        name: String,
        /// Attribute value or deletion tombstone.
        value: PaxValue<String>,
    },
    /// A reserved `security.*` extended attribute.
    Security {
        /// Keyword suffix after `security.`.
        name: String,
        /// Attribute value or deletion tombstone.
        value: PaxValue<String>,
    },
    /// Member payload size in octets.
    Size(PaxValue<u64>),
    /// Numeric user identifier.
    Uid(PaxValue<u64>),
    /// User name encoded according to the effective [`HdrCharset`].
    Uname(PaxValue<PaxString>),
    /// An implementation extension in the `VENDOR.keyword` namespace.
    Vendor {
        /// Uppercase ASCII vendor or organization identifier.
        vendor: String,
        /// Keyword suffix after the vendor namespace.
        name: String,
        /// Attribute value or deletion tombstone.
        value: PaxValue<String>,
    },
}

impl PaxRecord {
    /// Returns this record's PAX keyword exactly as it appears on the wire.
    pub fn keyword(&self) -> Cow<'_, str> {
        match self {
            Self::Atime(_) => Cow::Borrowed("atime"),
            Self::Charset(_) => Cow::Borrowed("charset"),
            Self::Comment(_) => Cow::Borrowed("comment"),
            Self::Ctime(_) => Cow::Borrowed("ctime"),
            Self::Gid(_) => Cow::Borrowed("gid"),
            Self::Gname(_) => Cow::Borrowed("gname"),
            Self::HdrCharset(_) => Cow::Borrowed("hdrcharset"),
            Self::LinkPath(_) => Cow::Borrowed("linkpath"),
            Self::Mtime(_) => Cow::Borrowed("mtime"),
            Self::Path(_) => Cow::Borrowed("path"),
            Self::Realtime { name, .. } => Cow::Owned(format!("realtime.{name}")),
            Self::Security { name, .. } => Cow::Owned(format!("security.{name}")),
            Self::Size(_) => Cow::Borrowed("size"),
            Self::Uid(_) => Cow::Borrowed("uid"),
            Self::Uname(_) => Cow::Borrowed("uname"),
            Self::Vendor { vendor, name, .. } => Cow::Owned(format!("{vendor}.{name}")),
        }
    }
}

pub(super) fn parse_records(
    position: u64,
    payload: &[u8],
    inherited_hdrcharset: HdrCharset,
) -> Result<Vec<PaxRecord>, FrameError> {
    if payload.is_empty() {
        return Err(FrameError::at(
            position,
            FrameErrorInner::InvalidPaxRecords {
                reason: "local extended header payload contains no records",
            },
        ));
    }

    let mut records = Vec::new();
    let mut cursor = 0;
    while cursor < payload.len() {
        let length_end = payload[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| {
                FrameError::at(
                    position,
                    FrameErrorInner::InvalidPaxRecords {
                        reason: "record is missing its length separator",
                    },
                )
            })?
            + cursor;
        if length_end == cursor {
            return Err(FrameError::at(
                position,
                FrameErrorInner::InvalidPaxRecords {
                    reason: "record length is empty",
                },
            ));
        }
        let record_len = std::str::from_utf8(&payload[cursor..length_end])
            .ok()
            .and_then(parse_integer)
            .ok_or_else(|| {
                FrameError::at(
                    position,
                    FrameErrorInner::InvalidPaxRecords {
                        reason: "record length is not a valid decimal integer",
                    },
                )
            })?;
        let record_len = usize::try_from(record_len).map_err(|_| {
            FrameError::at(
                position,
                FrameErrorInner::ArithmeticOverflow {
                    context: "pax record length",
                },
            )
        })?;
        let record_end = cursor.checked_add(record_len).ok_or_else(|| {
            FrameError::at(
                position,
                FrameErrorInner::ArithmeticOverflow {
                    context: "pax record end",
                },
            )
        })?;
        if record_end > payload.len() {
            return Err(FrameError::at(
                position,
                FrameErrorInner::InvalidPaxRecords {
                    reason: "record length exceeds extended header payload",
                },
            ));
        }
        let record = &payload[cursor..record_end];
        if record.last() != Some(&b'\n') {
            return Err(FrameError::at(
                position,
                FrameErrorInner::InvalidPaxRecords {
                    reason: "record is not newline terminated",
                },
            ));
        }
        let content_start = length_end - cursor + 1;
        let equals = record[content_start..record.len() - 1]
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| {
                FrameError::at(
                    position,
                    FrameErrorInner::InvalidPaxRecords {
                        reason: "record is missing its keyword/value separator",
                    },
                )
            })?
            + content_start;
        if equals == content_start {
            return Err(FrameError::at(
                position,
                FrameErrorInner::InvalidPaxRecords {
                    reason: "record keyword is empty",
                },
            ));
        }
        let keyword = std::str::from_utf8(&record[content_start..equals])
            .map_err(|_| FrameError::at(position, FrameErrorInner::InvalidPaxUtf8))?;
        records.push((keyword, &record[equals + 1..record.len() - 1]));
        cursor = record_end;
    }

    // Per pax spec: the `gname`, `linkpath`, `path`, and `uname` records
    // are encoded according to `hdrcharset`, so we need to first parse
    // it (or take it from a parent global pax header) before we can parse
    // the other pax records, regardless of order.
    //
    // See: pax spec, "pax Extended Header"
    let hdrcharset = record_hdrcharset(position, &records, inherited_hdrcharset)?;
    records
        .into_iter()
        .map(|(keyword, value)| parse_record(position, keyword, value, hdrcharset))
        .collect()
}

fn parse_record(
    position: u64,
    keyword: &str,
    value: &[u8],
    hdrcharset: HdrCharset,
) -> Result<PaxRecord, FrameError> {
    match keyword {
        "atime" => parse_time(position, "atime", value).map(PaxRecord::Atime),
        "charset" => parse_text(position, value).map(PaxRecord::Charset),
        "comment" => parse_text(position, value).map(PaxRecord::Comment),
        "ctime" => parse_time(position, "ctime", value).map(PaxRecord::Ctime),
        "gid" => parse_record_integer(position, "gid", value).map(PaxRecord::Gid),
        "gname" => parse_pax_string(position, value, hdrcharset).map(PaxRecord::Gname),
        "hdrcharset" => parse_hdrcharset(position, value).map(PaxRecord::HdrCharset),
        "linkpath" => parse_pax_string(position, value, hdrcharset).map(PaxRecord::LinkPath),
        "mtime" => parse_time(position, "mtime", value).map(PaxRecord::Mtime),
        "path" => parse_pax_string(position, value, hdrcharset).map(PaxRecord::Path),
        "size" => parse_record_integer(position, "size", value).map(PaxRecord::Size),
        "uid" => parse_record_integer(position, "uid", value).map(PaxRecord::Uid),
        "uname" => parse_pax_string(position, value, hdrcharset).map(PaxRecord::Uname),
        _ => parse_namespaced_record(position, keyword, value),
    }
}

fn parse_namespaced_record(
    position: u64,
    keyword: &str,
    value: &[u8],
) -> Result<PaxRecord, FrameError> {
    if let Some(name) = keyword.strip_prefix("realtime.")
        && !name.is_empty()
    {
        return Ok(PaxRecord::Realtime {
            name: name.to_owned(),
            value: parse_text(position, value)?,
        });
    }
    if let Some(name) = keyword.strip_prefix("security.")
        && !name.is_empty()
    {
        return Ok(PaxRecord::Security {
            name: name.to_owned(),
            value: parse_text(position, value)?,
        });
    }
    if let Some((vendor, name)) = keyword.split_once('.')
        && !vendor.is_empty()
        && vendor.bytes().all(|byte| byte.is_ascii_uppercase())
        && !name.is_empty()
    {
        return Ok(PaxRecord::Vendor {
            vendor: vendor.to_owned(),
            name: name.to_owned(),
            value: parse_text(position, value)?,
        });
    }
    Err(FrameError::at(
        position,
        FrameErrorInner::InvalidPaxKeyword {
            keyword: keyword.to_owned(),
        },
    ))
}

fn parse_text(position: u64, value: &[u8]) -> Result<PaxValue<String>, FrameError> {
    let value = parse_utf8(position, value)?;
    match value.parse() {
        Ok(value) => Ok(value),
        Err(error) => match error {},
    }
}

/// Parse a pax "string". This is distinct from [`parse_text`] or the common
/// underlying [`parse_utf8`] since it's [`HdrCharset`]-aware.
fn parse_pax_string(
    position: u64,
    value: &[u8],
    hdrcharset: HdrCharset,
) -> Result<PaxValue<PaxString>, FrameError> {
    if value.is_empty() {
        return Ok(PaxValue::Deleted);
    }
    match hdrcharset {
        HdrCharset::Utf8 => parse_utf8(position, value)
            .map(str::to_owned)
            .map(PaxString::Utf8)
            .map(PaxValue::Value),
        HdrCharset::Binary => Ok(PaxValue::Value(PaxString::Binary(value.to_vec()))),
    }
}

fn parse_hdrcharset(position: u64, value: &[u8]) -> Result<PaxValue<HdrCharset>, FrameError> {
    let value = parse_utf8(position, value)?;
    value
        .parse()
        .map_err(|value| FrameError::at(position, FrameErrorInner::UnsupportedPaxCharset { value }))
}

fn record_hdrcharset(
    position: u64,
    records: &[(&str, &[u8])],
    inherited: HdrCharset,
) -> Result<HdrCharset, FrameError> {
    let mut hdrcharset = inherited;
    for (keyword, value) in records {
        if *keyword == "hdrcharset" {
            hdrcharset = match parse_hdrcharset(position, value)? {
                PaxValue::Value(value) => value,
                PaxValue::Deleted => HdrCharset::Utf8,
            };
        }
    }
    Ok(hdrcharset)
}

fn parse_utf8(position: u64, value: &[u8]) -> Result<&str, FrameError> {
    std::str::from_utf8(value)
        .map_err(|_| FrameError::at(position, FrameErrorInner::InvalidPaxUtf8))
}

fn parse_record_integer(
    position: u64,
    keyword: &'static str,
    value: &[u8],
) -> Result<PaxValue<u64>, FrameError> {
    let value = parse_utf8(position, value)?;
    if value.is_empty() {
        return Ok(PaxValue::Deleted);
    }

    parse_integer(value).map(PaxValue::Value).ok_or_else(|| {
        FrameError::at(
            position,
            FrameErrorInner::InvalidPaxInteger {
                keyword,
                value: value.to_owned(),
            },
        )
    })
}

fn parse_time(
    position: u64,
    keyword: &'static str,
    value: &[u8],
) -> Result<PaxValue<u64>, FrameError> {
    let value = parse_utf8(position, value)?;
    if value.is_empty() {
        return Ok(PaxValue::Deleted);
    }

    let invalid = || {
        FrameError::at(
            position,
            FrameErrorInner::InvalidPaxTime {
                keyword,
                value: value.to_owned(),
            },
        )
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
    parse_integer(seconds)
        .map(PaxValue::Value)
        .ok_or_else(invalid)
}

pub(super) fn size(records: &[PaxRecord]) -> Option<&PaxValue<u64>> {
    records
        .iter()
        .filter_map(|record| match record {
            PaxRecord::Size(value) => Some(value),
            _ => None,
        })
        .next_back()
}

pub(super) fn hdrcharset(records: &[PaxRecord]) -> HdrCharset {
    records
        .iter()
        .filter_map(|record| match record {
            PaxRecord::HdrCharset(value) => Some(value),
            _ => None,
        })
        .next_back()
        .map_or(HdrCharset::Utf8, |value| match value {
            PaxValue::Value(value) => *value,
            PaxValue::Deleted => HdrCharset::Utf8,
        })
}

pub(super) fn apply_global(active: &mut Vec<PaxRecord>, records: Vec<PaxRecord>) {
    for record in records {
        let keyword = record.keyword();
        active.retain(|existing| existing.keyword() != keyword);
        active.push(record);
    }
}

fn parse_integer(value: &str) -> Option<u64> {
    if value.starts_with('+') {
        return None;
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{raw_record, record};

    fn vendor(name: &str, value: &str) -> PaxRecord {
        PaxRecord::Vendor {
            vendor: "ACME".to_owned(),
            name: name.to_owned(),
            value: PaxValue::Value(value.to_owned()),
        }
    }

    fn security(value: &str) -> PaxRecord {
        PaxRecord::Security {
            name: "label".to_owned(),
            value: PaxValue::Value(value.to_owned()),
        }
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
            parse_record_integer(0, "uid", b"12"),
            Ok(PaxValue::Value(12))
        ));
        assert!(matches!(
            parse_record_integer(0, "uid", b""),
            Ok(PaxValue::Deleted)
        ));
        assert!(matches!(
            parse_time(0, "mtime", b"12.034"),
            Ok(PaxValue::Value(12))
        ));
        assert!(matches!(parse_time(0, "mtime", b""), Ok(PaxValue::Deleted)));

        for value in ["+1", "-1", "12x", "18446744073709551616"] {
            assert!(matches!(
                parse_record_integer(7, "gid", value.as_bytes()),
                Err(FrameError {
                    position: 7,
                    inner: FrameErrorInner::InvalidPaxInteger { .. },
                })
            ));
        }
        for value in ["+1", "-1", "1.", "1.nanosecond", "18446744073709551616"] {
            assert!(matches!(
                parse_time(11, "atime", value.as_bytes()),
                Err(FrameError {
                    position: 11,
                    inner: FrameErrorInner::InvalidPaxTime { .. },
                })
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
            ("ACME.attribute", "custom"),
        ];
        let mut payload = Vec::new();
        for (keyword, value) in fields {
            payload.extend_from_slice(&record(keyword, value));
        }

        let Ok(records) = parse_records(0, &payload, HdrCharset::Utf8) else {
            panic!("records should parse");
        };
        assert_eq!(
            records,
            [
                PaxRecord::Atime(PaxValue::Value(12)),
                PaxRecord::Charset(PaxValue::Value("BINARY".to_owned())),
                PaxRecord::Comment(PaxValue::Value("a=b".to_owned())),
                PaxRecord::Ctime(PaxValue::Value(17)),
                PaxRecord::Gid(PaxValue::Value(7)),
                PaxRecord::Gname(PaxValue::Value(PaxString::Utf8("group".to_owned()))),
                PaxRecord::HdrCharset(PaxValue::Value(HdrCharset::Utf8)),
                PaxRecord::LinkPath(PaxValue::Value(PaxString::Utf8("target".to_owned()))),
                PaxRecord::Mtime(PaxValue::Value(42)),
                PaxRecord::Path(PaxValue::Value(PaxString::Utf8("file".to_owned()))),
                PaxRecord::Realtime {
                    name: "deadline".to_owned(),
                    value: PaxValue::Value("soon".to_owned()),
                },
                security("secure"),
                PaxRecord::Size(PaxValue::Value(0)),
                PaxRecord::Uid(PaxValue::Value(8)),
                PaxRecord::Uname(PaxValue::Value(PaxString::Utf8("user".to_owned()))),
                vendor("attribute", "custom"),
            ]
        );
        assert!(
            records
                .iter()
                .zip(fields)
                .all(|(record, (keyword, _))| record.keyword() == keyword)
        );
    }

    #[test]
    fn parses_deleted_ctime_compatibility_extension() {
        let Ok(records) = parse_records(0, &record("ctime", ""), HdrCharset::Utf8) else {
            panic!("ctime deletion should parse");
        };
        assert_eq!(records, vec![PaxRecord::Ctime(PaxValue::Deleted)]);
    }

    #[test]
    fn rejects_invalid_records_and_keywords_at_source_position() {
        for payload in [
            b"11 path=name".as_slice(),
            b"12 pathname\n".as_slice(),
            b"99 path=name\n".as_slice(),
            b"+12 path=name\n".as_slice(),
        ] {
            assert!(matches!(
                parse_records(23, payload, HdrCharset::Utf8),
                Err(FrameError {
                    position: 23,
                    inner: FrameErrorInner::InvalidPaxRecords { .. },
                })
            ));
        }

        let invalid_utf8 = raw_record(b"path", &[0xff]);
        assert!(matches!(
            parse_records(23, &invalid_utf8, HdrCharset::Utf8),
            Err(FrameError {
                position: 23,
                inner: FrameErrorInner::InvalidPaxUtf8,
            })
        ));

        for keyword in [
            "unknown",
            "lowercase.extension",
            "Vendor.attribute",
            "VENDOR",
            "VENDOR.",
            "realtime.",
            "security.",
        ] {
            assert!(matches!(
                parse_record(29, keyword, b"value", HdrCharset::Utf8),
                Err(FrameError {
                    position: 29,
                    inner: FrameErrorInner::InvalidPaxKeyword { .. },
                })
            ));
        }
    }

    #[test]
    fn applies_namespaced_globals_and_accepts_supported_hdrcharset_records() {
        let mut active = vec![
            vendor("first", "old"),
            vendor("second", "kept"),
            security("old"),
        ];
        apply_global(&mut active, vec![vendor("first", "new"), security("new")]);
        assert_eq!(
            active,
            [
                vendor("second", "kept"),
                vendor("first", "new"),
                security("new"),
            ]
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
                parse_records(0, &payload, HdrCharset::Utf8).is_ok(),
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
        let Ok(binary_records) = parse_records(0, &binary_values, HdrCharset::Utf8) else {
            panic!("binary records should parse");
        };
        assert_eq!(
            binary_records,
            [
                PaxRecord::HdrCharset(PaxValue::Value(HdrCharset::Binary)),
                PaxRecord::Gname(PaxValue::Value(PaxString::Binary(vec![0xfc]))),
                PaxRecord::LinkPath(PaxValue::Value(PaxString::Binary(vec![0xfd]))),
                PaxRecord::Path(PaxValue::Value(PaxString::Binary(vec![0xfe]))),
                PaxRecord::Uname(PaxValue::Value(PaxString::Binary(vec![0xff]))),
            ]
        );
        let inherited_binary_path = raw_record(b"path", &[0xfe]);
        let Ok(inherited_records) = parse_records(0, &inherited_binary_path, HdrCharset::Binary)
        else {
            panic!("inherited binary records should parse");
        };
        assert_eq!(
            inherited_records,
            [PaxRecord::Path(PaxValue::Value(PaxString::Binary(vec![
                0xfe
            ])))]
        );
        let mut reset_to_utf8 = record("hdrcharset", "");
        reset_to_utf8.extend_from_slice(&raw_record(b"path", &[0xfd]));
        assert!(matches!(
            parse_records(0, &reset_to_utf8, HdrCharset::Binary),
            Err(FrameError {
                inner: FrameErrorInner::InvalidPaxUtf8,
                ..
            })
        ));
        let mut binary_comment = record("hdrcharset", BINARY_HDRCHARSET);
        binary_comment.extend_from_slice(&raw_record(b"comment", &[0xff]));
        assert!(matches!(
            parse_records(0, &binary_comment, HdrCharset::Utf8),
            Err(FrameError {
                inner: FrameErrorInner::InvalidPaxUtf8,
                ..
            })
        ));

        let unsupported_value = "ISO-IR 8859 1 1998";
        let mut overridden_unsupported = record("hdrcharset", unsupported_value);
        overridden_unsupported.extend_from_slice(&record("hdrcharset", UTF8_HDRCHARSET));
        for unsupported in [
            record("hdrcharset", unsupported_value),
            overridden_unsupported,
        ] {
            assert!(matches!(
                parse_records(31, &unsupported, HdrCharset::Utf8),
                Err(FrameError {
                    position: 31,
                    inner: FrameErrorInner::UnsupportedPaxCharset { .. },
                })
            ));
        }
    }
}
