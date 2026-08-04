//! Empty DEFLATE blocks that carry backwards compressed-offset pointers.
//!
//! Adapted from `src/encode.rs` and `src/decode.rs` in David Tolnay's
//! `chapter-tgz` (MIT OR Apache-2.0): <https://github.com/dtolnay/chapter-tgz>.

use std::io;

pub(crate) const MAX_MARKER_BYTES: usize = 28;
pub(crate) const MAX_PREFIX_READ_BYTES: usize = 23;

const END_OF_BLOCK_SYMBOL: usize = 256;
const SHORT_ZERO_REPEAT_BASE: usize = 3;
const SHORT_ZERO_REPEAT_MAX: usize = 10;
const LONG_ZERO_REPEAT_BASE: usize = 11;
const LONG_ZERO_REPEAT_MAX: usize = 138;

// RFC 1951 transmits the code-length alphabet in this fixed permutation, not
// in numerical symbol order. Only three symbols need nonzero code lengths:
//
// - 17 repeats a zero code length 3..=10 times; its Huffman code is `0`.
// - 18 repeats a zero code length 11..=138 times; its Huffman code is `11`.
// - 1 assigns a one-bit code to the end-of-block and distance symbols.
//
// Symbol 15 is omitted because HCLEN declares only the first 18 entries.
const CODE_LENGTH_ALPHABET: [(u8, u8); 18] = [
    (16, 0),
    (17, 1),
    (18, 2),
    (0, 0),
    (8, 0),
    (7, 0),
    (9, 0),
    (6, 0),
    (10, 0),
    (5, 0),
    (11, 0),
    (4, 0),
    (12, 0),
    (3, 0),
    (13, 0),
    (2, 0),
    (14, 0),
    (1, 2),
];

#[derive(Clone)]
pub(crate) struct Marker {
    bytes: [u8; MAX_MARKER_BYTES],
    bit_len: usize,
}

impl Marker {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_MARKER_BYTES],
            bit_len: 0,
        }
    }

    /// Appends `width` low bits in DEFLATE's least-significant-bit-first order.
    fn push(&mut self, value: u8, width: usize) -> io::Result<()> {
        if width > u8::BITS as usize {
            return Err(io::Error::other("chapter marker field exceeds one byte"));
        }

        let byte_index = self.bit_len / 8;
        let bit_offset = self.bit_len % 8;
        let masked = u16::from(value) & ((1u16 << width) - 1);
        let shifted = masked << bit_offset;
        if let Some(byte) = self.bytes.get_mut(byte_index) {
            *byte |= shifted as u8;
        } else {
            return Err(io::Error::other("chapter marker exceeds its maximum size"));
        }
        if bit_offset + width > 8 {
            if let Some(byte) = self.bytes.get_mut(byte_index + 1) {
                *byte |= (shifted >> 8) as u8;
            } else {
                return Err(io::Error::other("chapter marker exceeds its maximum size"));
            }
        }
        self.bit_len += width;
        Ok(())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.bit_len.div_ceil(8)]
    }
}

/// Encodes a backward chapter distance as a valid, zero-output DEFLATE block.
///
/// The block's literal/length tree omits literal symbols 0 through 255 and
/// defines only symbol 256, the end-of-block marker. There are many valid ways
/// to run-length-encode those 256 zero code lengths. Each three-bit digit of
/// `distance` selects the length of a symbol-17 zero run, hiding the distance
/// in a Huffman description that ordinary DEFLATE readers process normally.
///
/// After those digits, symbol 18 and optional symbol-17 runs fill the remaining
/// zero lengths. One literal/length code and one distance code are then defined,
/// and the only actual compressed symbol immediately ends the block.
pub(crate) fn encode(final_block: bool, distance: u64) -> io::Result<Marker> {
    if distance == 0 {
        return Err(io::Error::other("chapter boundary distance cannot be zero"));
    }

    let mut marker = Marker::new();
    marker.push(u8::from(final_block), 1)?; // BFINAL: only the trailing marker ends DEFLATE.
    marker.push(0b10, 2)?; // BTYPE=10: dynamic Huffman block.
    marker.push(0, 5)?; // HLIT=0: 257 literal/length codes, ending at symbol 256.
    marker.push(0, 5)?; // HDIST=0: one distance code.
    marker.push(0b1110, 4)?; // HCLEN=14: 4 + 14 = 18 code-length alphabet entries.

    for (_, length) in CODE_LENGTH_ALPHABET {
        marker.push(length, 3)?;
    }

    // Code-length symbol 17 is encoded as one `0` bit followed by three extra
    // bits. Those extra bits select a run of 3 + digit zeros and double as one
    // little-endian octal digit of the backward distance.
    let mut remaining = distance;
    let mut zero_count = 0usize;
    while remaining != 0 {
        let digit = (remaining & 0b111) as u8;
        marker.push(0, 1)?; // Symbol 17: repeat a zero code length.
        marker.push(digit, 3)?; // Three extra bits: run length minus 3.
        zero_count += SHORT_ZERO_REPEAT_BASE + usize::from(digit);
        remaining >>= 3;
    }

    // The literal/length alphabet needs exactly 256 zero code lengths before
    // its end-of-block symbol. A u64 contributes between 4 and 214 zeros, so
    // choose the shortest compatible combination of zero-repeat symbols to
    // fill the remainder.
    match zero_count {
        4..=97 => {
            // 159..=252 zeros remain: one maximal 138-zero run followed by
            // another symbol-18 run of 21..=114 zeros.
            marker.push(0b11, 2)?; // Symbol 18: repeat 11..=138 zeros.
            marker.push(0b1111111, 7)?; // Extra value 127: 11 + 127 = 138 zeros.
            marker.push(0b11, 2)?; // Symbol 18 for the remaining zero lengths.
            marker.push(
                (END_OF_BLOCK_SYMBOL - (zero_count + LONG_ZERO_REPEAT_MAX) - LONG_ZERO_REPEAT_BASE)
                    as u8,
                7,
            )?;
        }
        98..=107 => {
            // 149..=158 zeros remain. One 129..=138-zero run and two maximal
            // 10-zero runs take 17 bits, one less than two symbol-18 runs.
            marker.push(0b11, 2)?;
            marker.push(
                (END_OF_BLOCK_SYMBOL
                    - (zero_count + 2 * SHORT_ZERO_REPEAT_MAX)
                    - LONG_ZERO_REPEAT_BASE) as u8,
                7,
            )?;
            marker.push(0, 1)?; // Symbol 17: repeat 3..=10 zeros.
            marker.push(0b111, 3)?; // Extra value 7: 3 + 7 = 10 zeros.
            marker.push(0, 1)?;
            marker.push(0b111, 3)?;
        }
        108..=117 => {
            // 139..=148 zeros remain: one 129..=138-zero run and one maximal
            // 10-zero symbol-17 run.
            marker.push(0b11, 2)?;
            marker.push(
                (END_OF_BLOCK_SYMBOL - (zero_count + SHORT_ZERO_REPEAT_MAX) - LONG_ZERO_REPEAT_BASE)
                    as u8,
                7,
            )?;
            marker.push(0, 1)?;
            marker.push(0b111, 3)?;
        }
        118..=214 => {
            // 42..=138 zeros remain and fit in one symbol-18 run.
            marker.push(0b11, 2)?;
            marker.push(
                (END_OF_BLOCK_SYMBOL - zero_count - LONG_ZERO_REPEAT_BASE) as u8,
                7,
            )?;
        }
        _ => return Err(io::Error::other("chapter marker has an invalid zero count")),
    }

    marker.push(0b01, 2)?; // Code-length symbol 1: one-bit end-of-block code.
    marker.push(0b01, 2)?; // Code-length symbol 1: one-bit distance code.
    marker.push(0, 1)?; // Literal/length symbol 256: immediately end the block.

    if !final_block {
        // The next chapter starts with a fresh raw DEFLATE encoder, whose
        // first block must begin at a byte boundary.
        let remainder = marker.bit_len % 8;
        if remainder == 6 {
            // A 10-bit empty fixed-Huffman block brings a 6-bit remainder to
            // the next byte boundary.
            marker.push(0, 1)?; // BFINAL=0.
            marker.push(0b01, 2)?; // BTYPE=01: fixed Huffman codes.
            marker.push(0, 7)?; // Fixed-Huffman end-of-block symbol.
        } else if remainder != 0 {
            // Otherwise an empty stored block provides an explicit byte
            // boundary: its three-bit header, alignment padding, LEN, NLEN.
            marker.push(0, 1)?; // BFINAL=0.
            marker.push(0, 2)?; // BTYPE=00: uncompressed stored block.
            marker.push(0, (8 - (remainder + 3) % 8) % 8)?; // Byte-align the header.
            marker.push(0, 8)?; // LEN low byte: empty block.
            marker.push(0, 8)?; // LEN high byte.
            marker.push(0xff, 8)?; // NLEN low byte: one's complement of LEN.
            marker.push(0xff, 8)?; // NLEN high byte.
        }
    }

    Ok(marker)
}

/// Returns the 72 marker bits that are independent of the chapter distance.
///
/// The dynamic-block header occupies 17 bits, and its 18 code-length alphabet
/// entries occupy another 54. Every nonzero distance starts with code-length
/// symbol 17, whose one-bit Huffman code is zero. Together those 17 + 54 + 1
/// bits form this byte-aligned signature; the first three distance bits start
/// immediately afterward. Only BFINAL differs between boundary and final
/// markers.
fn prefix(final_block: bool) -> [u8; 9] {
    [
        0b00000100 | u8::from(final_block), // BFINAL, BTYPE=10, HLIT=0.
        0b11000000,                         // HDIST=0 and the low HCLEN bits.
        0b00010001, // Last HCLEN bit, then symbol-16 and symbol-17 code lengths.
        0b00000001, // Symbol-18 code length, followed by unused alphabet entries.
        0,          // Unused code-length alphabet entries.
        0,
        0,
        0,
        0b00100000, // Symbol-1 code length, then the first symbol-17 Huffman bit.
    ]
}

pub(crate) fn decode_final(bytes: &[u8]) -> Option<(usize, u64)> {
    let expected = prefix(true);
    let mut start = bytes.len().checked_sub(13)?;
    while !bytes.get(start..)?.starts_with(&expected) {
        start = start.checked_sub(1)?;
    }
    decode_contents(bytes.get(start + expected.len()..)?).map(|distance| (start, distance))
}

pub(crate) fn decode_boundary(bytes: &[u8]) -> Option<u64> {
    let expected = prefix(false);
    if bytes.starts_with(&expected) {
        decode_contents(bytes.get(expected.len()..)?)
    } else {
        None
    }
}

fn decode_contents(bytes: &[u8]) -> Option<u64> {
    let mut bit_offset = 0usize;
    let mut take = |width: usize| -> Option<u8> {
        let first = u16::from(*bytes.get(bit_offset / 8)?);
        let second = u16::from(*bytes.get(bit_offset / 8 + 1).unwrap_or(&0));
        let value = (first | (second << 8)) >> (bit_offset % 8);
        bit_offset += width;
        Some((value & ((1u16 << width) - 1)) as u8)
    };

    let mut distance = 0u64;
    let mut zero_count = 0usize;
    let mut consumed_first_filler_bit = false;
    for index in 0..22 {
        if index > 0 && take(1)? != 0 {
            consumed_first_filler_bit = true;
            break;
        }
        let digit = take(3)?;
        if index == 21 && digit > 1 {
            return None;
        }
        distance |= u64::from(digit) << (index * 3);
        zero_count += 3 + usize::from(digit);
    }

    if distance == 0 || (!consumed_first_filler_bit && take(1)? != 1) || take(1)? != 1 {
        return None;
    }

    let valid_filler = match zero_count {
        4..=97 => {
            take(7)? == 0b1111111
                && take(2)? == 0b11
                && take(7)? == (256 - (zero_count + 138) - 11) as u8
        }
        98..=107 => {
            take(7)? == (256 - (zero_count + 20) - 11) as u8
                && take(1)? == 0
                && take(3)? == 0b111
                && take(1)? == 0
                && take(3)? == 0b111
        }
        108..=117 => {
            take(7)? == (256 - (zero_count + 10) - 11) as u8 && take(1)? == 0 && take(3)? == 0b111
        }
        118..=214 => take(7)? == (256 - zero_count - 11) as u8,
        _ => false,
    };

    if valid_filler && take(2)? == 1 && take(2)? == 1 && take(1)? == 0 {
        Some(distance)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{decode_boundary, decode_final, encode, prefix};

    #[test]
    fn matches_chapter_tgz_marker_encoding() -> io::Result<()> {
        let nonfinal = [
            0x04, 0xc0, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x21, 0xf9, 0xbf, 0xb7, 0x00,
            0x00, 0x00, 0xff, 0xff,
        ];
        let final_marker = [
            0x05, 0xc0, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x53, 0xf9, 0x7f, 0xb6, 0x00,
        ];

        assert_eq!(encode(false, 81)?.as_bytes(), nonfinal);
        assert_eq!(encode(true, 107)?.as_bytes(), final_marker);
        assert_eq!(decode_boundary(&nonfinal), Some(81));
        assert_eq!(decode_final(&final_marker), Some((0, 107)));
        Ok(())
    }

    #[test]
    fn round_trips_the_full_backward_distance_range() -> io::Result<()> {
        for distance in [
            1,
            7,
            8,
            81,
            100,
            107,
            255,
            256,
            65_535,
            0x3fff_ffff,
            0x1_ffff_ffff,
            u64::MAX,
        ] {
            let nonfinal = encode(false, distance)?;
            assert!(nonfinal.as_bytes().starts_with(&prefix(false)));
            assert_eq!(decode_boundary(nonfinal.as_bytes()), Some(distance));

            let final_marker = encode(true, distance)?;
            assert!(final_marker.as_bytes().starts_with(&prefix(true)));
            assert_eq!(decode_final(final_marker.as_bytes()), Some((0, distance)));
        }
        Ok(())
    }
}
