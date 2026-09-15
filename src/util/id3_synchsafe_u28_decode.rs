//! Decodes the four-byte synchsafe length field used by ID3 tags.
//!
//! `id3_synchsafe_u28_decode` — original: `FUN_080f81bc` at load address
//! `0x080f81bc` (**52 bytes**, `0x080f81bc..0x080f81f0`; thirteen ARM words
//! through `bx lr`). Raw `osos.dec` words establish that the separately linked
//! next function begins with `push {r4,lr}` at `0x080f81f0`. A complete decode
//! of every aligned ARM B/BL immediate finds **five direct inbound BL calls**,
//! all plain unconditional `bl` at `0x08120c70`, `0x08120d88`, `0x08121084`,
//! `0x08167428`, and `0x08282784`; there are no predicated BL callers.
//!
//! The function reads four bytes, discards bit 7 from each, and concatenates
//! their remaining seven-bit values as a big-endian 28-bit integer. No
//! deliberate deviations: the raw ARM code has no pointer guard and reads all
//! four bytes unconditionally.

/// Decodes a four-byte ID3 synchsafe length field.
///
/// # Safety
///
/// `bytes` must point to four readable bytes. The original does not check for
/// NULL or validate that each input byte is synchsafe.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn id3_synchsafe_u28_decode(bytes: *const u8) -> u32 {
    ((*bytes & 0x7f) as u32) << 21
        | ((*bytes.add(1) & 0x7f) as u32) << 14
        | ((*bytes.add(2) & 0x7f) as u32) << 7
        | (*bytes.add(3) & 0x7f) as u32
}

#[cfg(test)]
mod tests {
    use super::id3_synchsafe_u28_decode;

    fn reference_decode(bytes: [u8; 4]) -> u32 {
        bytes.into_iter().fold(0, |value, byte| (value << 7) | (byte & 0x7f) as u32)
    }

    #[test]
    fn decodes_id3_lengths_at_boundaries() {
        for (bytes, expected) in [
            ([0x00, 0x00, 0x00, 0x00], 0),
            ([0x00, 0x00, 0x02, 0x01], 257),
            ([0x7f, 0x7f, 0x7f, 0x7f], 0x0fff_ffff),
        ] {
            assert_eq!(unsafe { id3_synchsafe_u28_decode(bytes.as_ptr()) }, expected);
        }
    }

    #[test]
    fn ignores_the_high_bit_of_every_input_byte() {
        for bytes in [
            [0x80, 0x80, 0x80, 0x80],
            [0xff, 0x80, 0xff, 0x80],
            [0x80, 0xff, 0x80, 0xff],
        ] {
            assert_eq!(
                unsafe { id3_synchsafe_u28_decode(bytes.as_ptr()) },
                reference_decode(bytes),
            );
        }
    }
}
