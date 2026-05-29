use crate::Block;

pub(crate) const NAME_RANGE: std::ops::Range<usize> = 0..100;
pub(crate) const MODE_RANGE: std::ops::Range<usize> = 100..108;
pub(crate) const UID_RANGE: std::ops::Range<usize> = 108..116;
pub(crate) const GID_RANGE: std::ops::Range<usize> = 116..124;
pub(crate) const SIZE_RANGE: std::ops::Range<usize> = 124..136;
pub(crate) const MTIME_RANGE: std::ops::Range<usize> = 136..148;
pub(crate) const CHECKSUM_RANGE: std::ops::Range<usize> = 148..156;
pub(crate) const TYPEFLAG_OFFSET: usize = 156;
pub(crate) const LINK_NAME_RANGE: std::ops::Range<usize> = 157..257;
pub(crate) const IDENTITY_RANGE: std::ops::Range<usize> = 257..265;
pub(crate) const PREFIX_RANGE: std::ops::Range<usize> = 345..500;
pub(crate) const POSIX_IDENTITY: &[u8; 8] = b"ustar\x0000";
pub(crate) const GNU_IDENTITY: &[u8; 8] = b"ustar  \0";

pub(crate) fn checksum(block: &Block) -> u64 {
    block
        .iter()
        .enumerate()
        .map(|(offset, byte)| {
            if CHECKSUM_RANGE.contains(&offset) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum()
}

pub(crate) fn encode_checksum(block: &mut Block) -> bool {
    block[CHECKSUM_RANGE].fill(b' ');
    let encoded = format!("{:06o}\0 ", checksum(block));
    if encoded.len() != CHECKSUM_RANGE.len() {
        return false;
    }
    block[CHECKSUM_RANGE].copy_from_slice(encoded.as_bytes());
    true
}

pub(crate) fn encode_octal(field: &mut [u8], value: u64) -> bool {
    let encoded = format!("{value:o}");
    let Some(width) = field.len().checked_sub(1) else {
        return false;
    };
    if encoded.len() > width {
        return false;
    }
    field.fill(b'0');
    let start = width - encoded.len();
    field[start..width].copy_from_slice(encoded.as_bytes());
    field[width] = 0;
    true
}

pub(crate) fn parse_octal(bytes: &[u8]) -> Option<u64> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return None;
    }
    let terminator = bytes.iter().position(|byte| matches!(byte, 0 | b' '))?;
    if terminator == 0
        || bytes[..terminator]
            .iter()
            .any(|byte| !matches!(byte, b'0'..=b'7'))
    {
        return None;
    }
    if bytes[terminator..]
        .iter()
        .any(|byte| !matches!(byte, 0 | b' '))
    {
        return None;
    }
    bytes[..terminator].iter().try_fold(0_u64, |value, byte| {
        value.checked_mul(8)?.checked_add(u64::from(*byte - b'0'))
    })
}
