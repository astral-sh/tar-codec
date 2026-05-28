use std::str::FromStr;

use super::{FrameError, FrameErrorInner};

const UTF8_HDRCHARSET: &str = "ISO-IR 10646 2000 UTF-8";

/// A parsed pax value, including an explicit POSIX deletion tombstone.
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

/// A parsed POSIX pax extended-header record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaxRecord {
    /// File access time in integral seconds; fractional seconds are discarded.
    Atime(PaxValue<u64>),
    /// Encoding of the following member's file data.
    Charset(PaxValue<String>),
    /// An uninterpreted archive comment.
    Comment(PaxValue<String>),
    /// Numeric group identifier.
    Gid(PaxValue<u64>),
    /// Textual group name.
    Gname(PaxValue<String>),
    /// Encoding of extraction-critical extended-header values.
    HdrCharset(PaxValue<String>),
    /// Pathname stored as link contents or a hard-link target.
    LinkPath(PaxValue<String>),
    /// File modification time in integral seconds; fractional seconds are discarded.
    Mtime(PaxValue<u64>),
    /// Member pathname.
    Path(PaxValue<String>),
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
    /// Textual user name.
    Uname(PaxValue<String>),
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

/// The effect of pax `size` records within one precedence scope.
///
/// Local `x` records are consulted before active global `g` records, and
/// the raw member-header size is used only when both scopes are unspecified.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum PaxSize {
    /// No `size` record appears in this scope, so resolution continues outward.
    #[default]
    Unspecified,
    /// The last `size` record in this scope supplies a decimal member size.
    Value(u64),
    /// The last `size` record in this scope deletes any lower-precedence size.
    Deleted,
}

#[derive(Debug)]
struct WholeSeconds(u64);

#[derive(Debug)]
struct InvalidTimeValue;

impl FromStr for WholeSeconds {
    type Err = InvalidTimeValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let seconds = match value.split_once('.') {
            Some((seconds, fractional_digits))
                if !fractional_digits.is_empty()
                    && fractional_digits.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                seconds
            }
            Some(_) => return Err(InvalidTimeValue),
            None => value,
        };
        parse_decimal(seconds.as_bytes())
            .map(Self)
            .ok_or(InvalidTimeValue)
    }
}

pub(super) fn parse_records(position: u64, payload: &[u8]) -> Result<Vec<PaxRecord>, FrameError> {
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
        let record_len = parse_decimal(&payload[cursor..length_end]).ok_or_else(|| {
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
        let value = std::str::from_utf8(&record[equals + 1..record.len() - 1])
            .map_err(|_| FrameError::at(position, FrameErrorInner::InvalidPaxUtf8))?;
        records.push(parse_record(position, keyword, value)?);
        cursor = record_end;
    }

    if records.is_empty() {
        return Err(FrameError::at(
            position,
            FrameErrorInner::InvalidPaxRecords {
                reason: "local extended header payload contains no records",
            },
        ));
    }
    Ok(records)
}

fn parse_record(position: u64, keyword: &str, value: &str) -> Result<PaxRecord, FrameError> {
    match keyword {
        "atime" => parse_time(position, "atime", value).map(PaxRecord::Atime),
        "charset" => Ok(PaxRecord::Charset(parse_text(value))),
        "comment" => Ok(PaxRecord::Comment(parse_text(value))),
        "gid" => parse_integer(position, "gid", value).map(PaxRecord::Gid),
        "gname" => Ok(PaxRecord::Gname(parse_text(value))),
        "hdrcharset" => Ok(PaxRecord::HdrCharset(parse_text(value))),
        "linkpath" => Ok(PaxRecord::LinkPath(parse_text(value))),
        "mtime" => parse_time(position, "mtime", value).map(PaxRecord::Mtime),
        "path" => Ok(PaxRecord::Path(parse_text(value))),
        "size" => parse_integer(position, "size", value).map(PaxRecord::Size),
        "uid" => parse_integer(position, "uid", value).map(PaxRecord::Uid),
        "uname" => Ok(PaxRecord::Uname(parse_text(value))),
        _ => parse_namespaced_record(position, keyword, value),
    }
}

fn parse_namespaced_record(
    position: u64,
    keyword: &str,
    value: &str,
) -> Result<PaxRecord, FrameError> {
    if let Some(name) = keyword.strip_prefix("realtime.")
        && !name.is_empty()
    {
        return Ok(PaxRecord::Realtime {
            name: name.to_owned(),
            value: parse_text(value),
        });
    }
    if let Some(name) = keyword.strip_prefix("security.")
        && !name.is_empty()
    {
        return Ok(PaxRecord::Security {
            name: name.to_owned(),
            value: parse_text(value),
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
            value: parse_text(value),
        });
    }
    Err(FrameError::at(
        position,
        FrameErrorInner::InvalidPaxKeyword {
            keyword: keyword.to_owned(),
        },
    ))
}

fn parse_text(value: &str) -> PaxValue<String> {
    match value.parse() {
        Ok(value) => value,
        Err(error) => match error {},
    }
}

fn parse_integer(
    position: u64,
    keyword: &'static str,
    value: &str,
) -> Result<PaxValue<u64>, FrameError> {
    let invalid = || {
        FrameError::at(
            position,
            FrameErrorInner::InvalidPaxInteger {
                keyword,
                value: value.to_owned(),
            },
        )
    };
    let parsed = value.parse::<PaxValue<u64>>().map_err(|_| invalid())?;

    // `u64::from_str` allows a leading `+`, which we must reject.
    if value.starts_with('+') {
        return Err(invalid());
    }
    Ok(parsed)
}

fn parse_time(
    position: u64,
    keyword: &'static str,
    value: &str,
) -> Result<PaxValue<u64>, FrameError> {
    value
        .parse::<PaxValue<WholeSeconds>>()
        .map(map_seconds)
        .map_err(|_| {
            FrameError::at(
                position,
                FrameErrorInner::InvalidPaxTime {
                    keyword,
                    value: value.to_owned(),
                },
            )
        })
}

fn map_seconds(value: PaxValue<WholeSeconds>) -> PaxValue<u64> {
    match value {
        PaxValue::Value(WholeSeconds(value)) => PaxValue::Value(value),
        PaxValue::Deleted => PaxValue::Deleted,
    }
}

pub(super) fn size(records: &[PaxRecord]) -> PaxSize {
    let mut size = PaxSize::Unspecified;
    for record in records {
        if let PaxRecord::Size(value) = record {
            size = match value {
                PaxValue::Value(size) => PaxSize::Value(*size),
                PaxValue::Deleted => PaxSize::Deleted,
            };
        }
    }
    size
}

pub(super) fn validate_charset(position: u64, records: &[PaxRecord]) -> Result<(), FrameError> {
    if let Some(charset) = records.iter().rev().find_map(|record| match record {
        PaxRecord::HdrCharset(value) => Some(value),
        _ => None,
    }) && let PaxValue::Value(charset) = charset
        && charset != UTF8_HDRCHARSET
    {
        return Err(FrameError::at(
            position,
            FrameErrorInner::UnsupportedPaxCharset {
                value: charset.clone(),
            },
        ));
    }
    Ok(())
}

pub(super) fn apply_global(active: &mut Vec<PaxRecord>, records: Vec<PaxRecord>) {
    for record in records {
        active.retain(|existing| !same_keyword(existing, &record));
        active.push(record);
    }
}

fn same_keyword(left: &PaxRecord, right: &PaxRecord) -> bool {
    match (left, right) {
        (PaxRecord::Atime(_), PaxRecord::Atime(_))
        | (PaxRecord::Charset(_), PaxRecord::Charset(_))
        | (PaxRecord::Comment(_), PaxRecord::Comment(_))
        | (PaxRecord::Gid(_), PaxRecord::Gid(_))
        | (PaxRecord::Gname(_), PaxRecord::Gname(_))
        | (PaxRecord::HdrCharset(_), PaxRecord::HdrCharset(_))
        | (PaxRecord::LinkPath(_), PaxRecord::LinkPath(_))
        | (PaxRecord::Mtime(_), PaxRecord::Mtime(_))
        | (PaxRecord::Path(_), PaxRecord::Path(_))
        | (PaxRecord::Size(_), PaxRecord::Size(_))
        | (PaxRecord::Uid(_), PaxRecord::Uid(_))
        | (PaxRecord::Uname(_), PaxRecord::Uname(_)) => true,
        (PaxRecord::Realtime { name: left, .. }, PaxRecord::Realtime { name: right, .. })
        | (PaxRecord::Security { name: left, .. }, PaxRecord::Security { name: right, .. }) => {
            left == right
        }
        (
            PaxRecord::Vendor {
                vendor: left_vendor,
                name: left_name,
                ..
            },
            PaxRecord::Vendor {
                vendor: right_vendor,
                name: right_name,
                ..
            },
        ) => left_vendor == right_vendor && left_name == right_name,
        _ => false,
    }
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_record(keyword: &str, value: &str) -> Vec<u8> {
        let suffix = format!(" {keyword}={value}\n");
        let mut len = suffix.len() + 1;
        loop {
            let encoded = format!("{len}{suffix}");
            if encoded.len() == len {
                return encoded.into_bytes();
            }
            len = encoded.len();
        }
    }

    fn encoded_raw_record(keyword: &[u8], value: &[u8]) -> Vec<u8> {
        let mut suffix = Vec::new();
        suffix.push(b' ');
        suffix.extend_from_slice(keyword);
        suffix.push(b'=');
        suffix.extend_from_slice(value);
        suffix.push(b'\n');
        let mut len = suffix.len() + 1;
        loop {
            let prefix = len.to_string();
            let actual = prefix.len() + suffix.len();
            if actual == len {
                let mut record = prefix.into_bytes();
                record.extend_from_slice(&suffix);
                return record;
            }
            len = actual;
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
            parse_integer(0, "uid", "12"),
            Ok(PaxValue::Value(12))
        ));
        assert!(matches!(parse_integer(0, "uid", ""), Ok(PaxValue::Deleted)));
        assert!(matches!(
            parse_time(0, "mtime", "12.034"),
            Ok(PaxValue::Value(12))
        ));
        assert!(matches!(parse_time(0, "mtime", ""), Ok(PaxValue::Deleted)));

        for value in ["+1", "-1", "12x", "18446744073709551616"] {
            assert!(matches!(
                parse_integer(7, "gid", value),
                Err(FrameError {
                    position: 7,
                    inner: FrameErrorInner::InvalidPaxInteger { .. },
                })
            ));
        }
        for value in ["+1", "-1", "1.", "1.nanosecond", "18446744073709551616"] {
            assert!(matches!(
                parse_time(11, "atime", value),
                Err(FrameError {
                    position: 11,
                    inner: FrameErrorInner::InvalidPaxTime { .. },
                })
            ));
        }
    }

    #[test]
    fn parses_typed_standard_reserved_and_vendor_records() {
        let mut payload = encoded_record("atime", "12.034");
        for (keyword, value) in [
            ("charset", "BINARY"),
            ("comment", "a=b"),
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
        ] {
            payload.extend_from_slice(&encoded_record(keyword, value));
        }

        let Ok(records) = parse_records(0, &payload) else {
            panic!("records should parse");
        };
        assert_eq!(
            records,
            [
                PaxRecord::Atime(PaxValue::Value(12)),
                PaxRecord::Charset(PaxValue::Value("BINARY".to_owned())),
                PaxRecord::Comment(PaxValue::Value("a=b".to_owned())),
                PaxRecord::Gid(PaxValue::Value(7)),
                PaxRecord::Gname(PaxValue::Value("group".to_owned())),
                PaxRecord::HdrCharset(PaxValue::Value(UTF8_HDRCHARSET.to_owned())),
                PaxRecord::LinkPath(PaxValue::Value("target".to_owned())),
                PaxRecord::Mtime(PaxValue::Value(42)),
                PaxRecord::Path(PaxValue::Value("file".to_owned())),
                PaxRecord::Realtime {
                    name: "deadline".to_owned(),
                    value: PaxValue::Value("soon".to_owned()),
                },
                PaxRecord::Security {
                    name: "label".to_owned(),
                    value: PaxValue::Value("secure".to_owned()),
                },
                PaxRecord::Size(PaxValue::Value(0)),
                PaxRecord::Uid(PaxValue::Value(8)),
                PaxRecord::Uname(PaxValue::Value("user".to_owned())),
                PaxRecord::Vendor {
                    vendor: "ACME".to_owned(),
                    name: "attribute".to_owned(),
                    value: PaxValue::Value("custom".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn rejects_invalid_records_and_keywords_at_source_position() {
        for payload in [
            b"11 path=name".as_slice(),
            b"12 pathname\n".as_slice(),
            b"99 path=name\n".as_slice(),
        ] {
            assert!(matches!(
                parse_records(23, payload),
                Err(FrameError {
                    position: 23,
                    inner: FrameErrorInner::InvalidPaxRecords { .. },
                })
            ));
        }

        let invalid_utf8 = encoded_raw_record(b"path", &[0xff]);
        assert!(matches!(
            parse_records(23, &invalid_utf8),
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
                parse_record(29, keyword, "value"),
                Err(FrameError {
                    position: 29,
                    inner: FrameErrorInner::InvalidPaxKeyword { .. },
                })
            ));
        }
    }

    #[test]
    fn applies_namespaced_globals_and_charset_precedence() {
        let mut active = vec![
            PaxRecord::Vendor {
                vendor: "ACME".to_owned(),
                name: "first".to_owned(),
                value: PaxValue::Value("old".to_owned()),
            },
            PaxRecord::Vendor {
                vendor: "ACME".to_owned(),
                name: "second".to_owned(),
                value: PaxValue::Value("kept".to_owned()),
            },
            PaxRecord::Security {
                name: "label".to_owned(),
                value: PaxValue::Value("old".to_owned()),
            },
        ];
        apply_global(
            &mut active,
            vec![
                PaxRecord::Vendor {
                    vendor: "ACME".to_owned(),
                    name: "first".to_owned(),
                    value: PaxValue::Value("new".to_owned()),
                },
                PaxRecord::Security {
                    name: "label".to_owned(),
                    value: PaxValue::Value("new".to_owned()),
                },
            ],
        );
        assert_eq!(
            active,
            [
                PaxRecord::Vendor {
                    vendor: "ACME".to_owned(),
                    name: "second".to_owned(),
                    value: PaxValue::Value("kept".to_owned()),
                },
                PaxRecord::Vendor {
                    vendor: "ACME".to_owned(),
                    name: "first".to_owned(),
                    value: PaxValue::Value("new".to_owned()),
                },
                PaxRecord::Security {
                    name: "label".to_owned(),
                    value: PaxValue::Value("new".to_owned()),
                },
            ]
        );

        assert!(matches!(
            validate_charset(
                0,
                &[
                    PaxRecord::HdrCharset(PaxValue::Value("BINARY".to_owned())),
                    PaxRecord::HdrCharset(PaxValue::Value(UTF8_HDRCHARSET.to_owned())),
                ]
            ),
            Ok(())
        ));
        assert!(matches!(
            validate_charset(
                31,
                &[PaxRecord::HdrCharset(PaxValue::Value("BINARY".to_owned()))]
            ),
            Err(FrameError {
                position: 31,
                inner: FrameErrorInner::UnsupportedPaxCharset { .. },
            })
        ));
    }
}
