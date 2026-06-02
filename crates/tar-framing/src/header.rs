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

pub(crate) fn encode_checksum_value(block: &mut Block, value: u64) -> bool {
    encode_octal_with_suffix(&mut block[CHECKSUM_RANGE], value, b"\0 ")
}

pub(crate) fn encode_octal(field: &mut [u8], value: u64) -> bool {
    encode_octal_with_suffix(field, value, b"\0")
}

fn encode_octal_with_suffix(field: &mut [u8], value: u64, suffix: &[u8]) -> bool {
    let Some(width) = field.len().checked_sub(suffix.len()) else {
        return false;
    };
    if width == 0 {
        return false;
    }
    field[..width].fill(b'0');
    field[width..].copy_from_slice(suffix);
    encode_octal_digits(&mut field[..width], value)
}

fn encode_octal_digits(field: &mut [u8], mut value: u64) -> bool {
    for byte in field.iter_mut().rev() {
        *byte = b'0' + (value & 0o7) as u8;
        value >>= 3;
    }
    value == 0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_octal_values_that_fit_the_field() {
        let mut field = [0xff; 4];
        assert!(encode_octal(&mut field, 0o17));
        assert_eq!(&field, b"017\0");
        assert_eq!(parse_octal(&field), Some(0o17));

        assert!(encode_octal(&mut field, 0o777));
        assert_eq!(&field, b"777\0");
        assert!(!encode_octal(&mut field, 0o1000));
        assert!(!encode_octal(&mut [], 0));
        assert!(!encode_octal(&mut [0], 0));
    }

    #[test]
    fn encodes_checksum_with_the_standard_terminator() {
        let mut block = [0; crate::BLOCK_SIZE];
        block[0] = b'x';
        let value = checksum(&block);
        assert!(encode_checksum_value(&mut block, value));
        assert_eq!(parse_octal(&block[CHECKSUM_RANGE]), Some(checksum(&block)));
        assert_eq!(&block[CHECKSUM_RANGE.end - 2..CHECKSUM_RANGE.end], b"\0 ");
    }
}
