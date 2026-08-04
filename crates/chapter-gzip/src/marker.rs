//! Empty DEFLATE blocks that carry backwards compressed-offset pointers.

use std::io;

pub(crate) const MAX_MARKER_BYTES: usize = 28;
pub(crate) const MAX_PREFIX_READ_BYTES: usize = 23;

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

pub(crate) fn encode(final_block: bool, distance: u64) -> io::Result<Marker> {
    if distance == 0 {
        return Err(io::Error::other("chapter boundary distance cannot be zero"));
    }

    let mut marker = Marker::new();
    marker.push(u8::from(final_block), 1)?;
    marker.push(0b10, 2)?;
    marker.push(0, 5)?;
    marker.push(0, 5)?;
    marker.push(0b1110, 4)?;

    for length in [0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2] {
        marker.push(length, 3)?;
    }

    let mut remaining = distance;
    let mut zero_count = 0usize;
    while remaining != 0 {
        let digit = (remaining & 0b111) as u8;
        marker.push(0, 1)?;
        marker.push(digit, 3)?;
        zero_count += 3 + usize::from(digit);
        remaining >>= 3;
    }

    match zero_count {
        4..=97 => {
            marker.push(0b11, 2)?;
            marker.push(0b1111111, 7)?;
            marker.push(0b11, 2)?;
            marker.push((256 - (zero_count + 138) - 11) as u8, 7)?;
        }
        98..=107 => {
            marker.push(0b11, 2)?;
            marker.push((256 - (zero_count + 20) - 11) as u8, 7)?;
            marker.push(0, 1)?;
            marker.push(0b111, 3)?;
            marker.push(0, 1)?;
            marker.push(0b111, 3)?;
        }
        108..=117 => {
            marker.push(0b11, 2)?;
            marker.push((256 - (zero_count + 10) - 11) as u8, 7)?;
            marker.push(0, 1)?;
            marker.push(0b111, 3)?;
        }
        118..=214 => {
            marker.push(0b11, 2)?;
            marker.push((256 - zero_count - 11) as u8, 7)?;
        }
        _ => return Err(io::Error::other("chapter marker has an invalid zero count")),
    }

    marker.push(0b01, 2)?;
    marker.push(0b01, 2)?;
    marker.push(0, 1)?;

    if !final_block {
        let remainder = marker.bit_len % 8;
        if remainder == 6 {
            marker.push(0, 1)?;
            marker.push(0b01, 2)?;
            marker.push(0, 7)?;
        } else if remainder != 0 {
            marker.push(0, 1)?;
            marker.push(0, 2)?;
            marker.push(0, (13 - remainder) % 8)?;
            marker.push(0, 8)?;
            marker.push(0, 8)?;
            marker.push(0xff, 8)?;
            marker.push(0xff, 8)?;
        }
    }

    Ok(marker)
}

fn prefix(final_block: bool) -> [u8; 9] {
    [
        0b00000100 | u8::from(final_block),
        0b11000000,
        0b00010001,
        0b00000001,
        0,
        0,
        0,
        0,
        0b00100000,
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

    use super::{decode_boundary, decode_final, encode};

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
        for distance in [1, 7, 8, 81, 100, 107, 255, 256, 65_535, u64::MAX] {
            let nonfinal = encode(false, distance)?;
            assert_eq!(decode_boundary(nonfinal.as_bytes()), Some(distance));

            let final_marker = encode(true, distance)?;
            assert_eq!(decode_final(final_marker.as_bytes()), Some((0, distance)));
        }
        Ok(())
    }
}
