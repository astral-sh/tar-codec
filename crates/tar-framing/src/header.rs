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

// Pax framing constructs two headers per member. Keeping this fixed-size
// reduction inline lets LLVM lower each call to a compact vectorized sum.
#[inline(always)]
pub(crate) fn checksum(block: &Block) -> u64 {
    // A block's maximum byte sum fits in u32, which gives LLVM a compact
    // vectorized reduction.
    let block_sum = block.iter().map(|byte| u32::from(*byte)).sum::<u32>();
    let checksum_sum = block[CHECKSUM_RANGE]
        .iter()
        .map(|byte| u32::from(*byte))
        .sum::<u32>();
    u64::from(block_sum - checksum_sum + CHECKSUM_RANGE.len() as u32 * u32::from(b' '))
}

#[inline(always)]
pub(crate) fn encode_checksum(block: &mut Block) {
    let value = checksum(block);
    // Six octal digits can represent every possible block checksum.
    let _ = encode_octal_with_suffix(&mut block[CHECKSUM_RANGE], value, b"\0 ");
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
    let mut value = 0_u64;
    let mut has_digits = false;
    let mut terminated = false;
    for byte in bytes {
        match *byte {
            b'0'..=b'7' if !terminated => {
                value = value.checked_mul(8)?.checked_add(u64::from(*byte - b'0'))?;
                has_digits = true;
            }
            0 | b' ' => terminated = true,
            _ => return None,
        }
    }
    (has_digits && terminated).then_some(value)
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
    fn parses_strict_octal_fields() {
        for (field, expected) in [
            (&b"17\0"[..], Some(0o17)),
            (&b"17 \0"[..], Some(0o17)),
            (&b""[..], None),
            (&b"\0"[..], None),
            (&b"17"[..], None),
            (&b"18\0"[..], None),
            (&b"1\0\x32"[..], None),
            (&[0x80, 0][..], None),
        ] {
            assert_eq!(parse_octal(field), expected, "{field:?}");
        }

        let mut overflow = [b'7'; 24];
        overflow[23] = 0;
        assert_eq!(parse_octal(&overflow), None);
    }

    #[test]
    fn encodes_checksum_with_the_standard_terminator() {
        let mut block = [0; crate::BLOCK_SIZE];
        block[0] = b'x';
        let value = checksum(&block);
        encode_checksum(&mut block);
        assert_eq!(parse_octal(&block[CHECKSUM_RANGE]), Some(value));
        assert_eq!(&block[CHECKSUM_RANGE.end - 2..CHECKSUM_RANGE.end], b"\0 ");
    }

    #[test]
    fn checksum_treats_its_field_as_spaces() {
        let mut block = [0xff; crate::BLOCK_SIZE];
        block[CHECKSUM_RANGE].fill(0);

        let expected = (crate::BLOCK_SIZE - CHECKSUM_RANGE.len()) as u64 * u64::from(u8::MAX)
            + CHECKSUM_RANGE.len() as u64 * u64::from(b' ');
        assert_eq!(checksum(&block), expected);

        block[CHECKSUM_RANGE].fill(0xff);
        assert_eq!(checksum(&block), expected);

        encode_checksum(&mut block);
        assert_eq!(parse_octal(&block[CHECKSUM_RANGE]), Some(expected));
    }
}
