use crate::{ArchiveFormat, Block};

pub const NAME_RANGE: std::ops::Range<usize> = 0..100;
pub const MODE_RANGE: std::ops::Range<usize> = 100..108;
pub const UID_RANGE: std::ops::Range<usize> = 108..116;
pub const GID_RANGE: std::ops::Range<usize> = 116..124;
pub const SIZE_RANGE: std::ops::Range<usize> = 124..136;
pub const MTIME_RANGE: std::ops::Range<usize> = 136..148;
pub const CHECKSUM_RANGE: std::ops::Range<usize> = 148..156;
pub const TYPEFLAG_OFFSET: usize = 156;
pub const LINK_NAME_RANGE: std::ops::Range<usize> = 157..257;
pub const IDENTITY_RANGE: std::ops::Range<usize> = 257..265;
pub const PREFIX_RANGE: std::ops::Range<usize> = 345..500;
/// The magic and version bytes for a ustar tar block.
/// ustar blocks form the baseline for pax, since every pax block is
/// a well-formed ustar block (and what makes it pax is whether
/// it uses a pax typeflag).
pub const USTAR_IDENTITY: &[u8; 8] = b"ustar\x0000";
/// The magic and version bytes for a GNU tar block.
pub const GNU_IDENTITY: &[u8; 8] = b"ustar  \0";

/// A tar header block (pax, ustar, or GNU) is exactly 512 bytes,
/// so the logical maximum checksum is `255*512 = 130,560`. However,
/// the checksum field *itself* is treated as 8 ASCII spaces when
/// computing the checksum, so the actual maximum is
/// `(504*255)+(8*32) = 128,776`.
const MAX_CHECKSUM: u64 = (504 * 255) + (8 * 32);
const _: () = assert!(MAX_CHECKSUM < 0o777777);

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

    // Observe:
    // 1. We know statically that our computed checksum is no more than MAX_CHECKSUM
    // 2. We know that MAX_CHECKSUM is less than 0o777777 (262143)
    //
    // Therefore, we know that all possible checksums fit within 6 octal digits,
    // and therefore we can always safely include two padding bytes.
    //
    // NOTE: the use of `\0 ` as the suffix is not specified by pax, but appears
    // to be a convention across tar encoders.
    debug_assert!(value <= MAX_CHECKSUM);
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

/// Parse an octal number from the given bytes.
///
/// Per pax, an octal number is a leading-zero filled sequence of octal characters
/// (0-7), terminated by one or more NUL or space characters.
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

/// Parse a number from the given bytes, depending on the archive format.
///
/// See [`parse_octal`] for the pax parsing rules and [`parse_gnu_number`]
/// for the GNU parsing rules.
pub(crate) fn parse_number(format: ArchiveFormat, bytes: &[u8]) -> Option<u64> {
    match format {
        ArchiveFormat::Pax => parse_octal(bytes),
        ArchiveFormat::Gnu => parse_gnu_number(bytes),
    }
}

/// Parse a number according to the GNU tar rules.
///
/// This implements a subset of the GNU rules: negative numbers are rejected entirely,
/// and we don't reject base256 encodings that *would* fit in the octal encoding.
/// TODO: Consider rejecting these? The GNU spec describes base256 encodings that would
/// fit in octal as "reserved for future use."
fn parse_gnu_number(bytes: &[u8]) -> Option<u64> {
    match bytes.first()? {
        0x80 => bytes[1..].iter().try_fold(0_u64, |value, byte| {
            value.checked_mul(256)?.checked_add(u64::from(*byte))
        }),
        // Negative encoding; reject for now. This would also be rejected by
        // `parse_octal` but here is clearer.
        0xff => None,
        _ => parse_octal(bytes),
    }
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
            // OK: leading zeroes.
            (&b"000017 "[..], Some(0o17)),
            (&b"0000000000000000000000000000017 "[..], Some(0o17)),
            // OK: 0o17, null terminated.
            (&b"17\0"[..], Some(0o17)),
            // OK: 0o17, space terminated.
            (&b"17 "[..], Some(0o17)),
            // OK: 0o17, space terminated (trailing null ignored)
            (&b"17 \0"[..], Some(0o17)),
            // Invalid: empty
            (&b""[..], None),
            // Invalid: terminator only
            (&b"\0"[..], None),
            (&b" "[..], None),
            // Invalid: no terminator
            (&b"17"[..], None),
            // Invalid: not in octal domain
            (&b"18\0"[..], None),
            // Invalid: not in octal domain, even after terminator
            (&b"1\0\x32"[..], None),
            // Invalid: octal after terminator.
            (&b"1\0\x31"[..], None),
            (&b"1 1"[..], None),
            // Invalid: not in octal domain.
            (&[0x80, 0][..], None),
            // Invalid: overflows u64.
            (&b"77777777777777777777777 "[..], None),
            (&b"77777777777777777777777\0"[..], None),
        ] {
            assert_eq!(parse_octal(field), expected, "{field:?}");
        }
    }

    #[test]
    fn checksums_known_blocks() {
        let zero_block = [0; crate::BLOCK_SIZE];
        let mut x_typeflag_block = zero_block;
        x_typeflag_block[TYPEFLAG_OFFSET] = b'x';
        x_typeflag_block[CHECKSUM_RANGE].fill(0xff);
        let maximum_block = [0xff; crate::BLOCK_SIZE];

        for (name, mut block, expected) in [
            ("zero block", zero_block, b"000400\0 "),
            (
                "x typeflag with junk checksum bytes",
                x_typeflag_block,
                b"000570\0 ",
            ),
            ("maximum block", maximum_block, b"373410\0 "),
        ] {
            assert_eq!(Some(checksum(&block)), parse_octal(expected), "{name}");
            encode_checksum(&mut block);
            assert_eq!(&block[CHECKSUM_RANGE], expected, "{name}");
        }
    }
}
