//! `rgba8_to_rgba8888` — original: `FUN_082a0100` @ `0x082a0100` (36 bytes;
//! **4 unconditional `bl` call sites**, no predicated `bl` call sites,
//! binary-scanned by decoding every ARM B/BL word in `osos.dec`).
//!
//! The raw body begins with `ldrb r1,[r0]` and ends with `bx lr` at
//! `0x082a0120`; the next separately linked function begins at `0x082a0124`,
//! so the complete extent is nine instructions with no literal pool. It reads
//! four RGBA8 bytes in order and returns them as the u32 `0xRRGGBBAA`. It has
//! no NULL, alignment, or bounds guard.
//!
//! # Deliberate deviations
//!
//! None. The ARM return-register value is represented directly as `u32`.

/// Packs four RGBA8 component bytes into a `0xRRGGBBAA` u32.
///
/// # Safety
///
/// `components` must identify four readable bytes in R, G, B, A order.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.rgba8_to_rgba8888")]
#[inline(never)]
pub unsafe extern "C" fn rgba8_to_rgba8888(components: *const u8) -> u32 {
    (u32::from(*components) << 24)
        | (u32::from(*components.add(1)) << 16)
        | (u32::from(*components.add(2)) << 8)
        | u32::from(*components.add(3))
}

/// `rgba8_packed_equal` — original: `FUN_082a0124` @ `0x082a0124`
/// (40 bytes; 2 unconditional incoming `bl` sites at `0x0829fad8` and
/// `0x0829ff78`, zero predicated sites, verified by raw ARM-word decoding).
///
/// Packs the left then right four-byte RGBA record through
/// `rgba8_to_rgba8888` (`0x082a0100`) and returns 1 iff the words match,
/// otherwise 0. The two outgoing BLs are unconditional. The body ends with
/// `pop {r4,r5,r6,pc}` at `0x082a0148`; the next function starts at
/// `0x082a014c`, with no intervening literal pool. Deliberate deviations: none.
///
/// # Safety
///
/// Both pointers must identify four readable bytes; alignment is unrestricted.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.rgba8_packed_equal")]
#[inline(never)]
pub unsafe extern "C" fn rgba8_packed_equal(left: *const u8, right: *const u8) -> u32 {
    let left_word = rgba8_to_rgba8888(left);
    let right_word = rgba8_to_rgba8888(right);
    u32::from(left_word == right_word)
}

#[cfg(test)]
mod tests {
    use super::{rgba8_packed_equal, rgba8_to_rgba8888};

    #[test]
    fn packs_each_component_in_rgba_order() {
        let components = [0x12, 0x34, 0x56, 0x78];

        assert_eq!(unsafe { rgba8_to_rgba8888(components.as_ptr()) }, 0x1234_5678);
    }

    #[test]
    fn reads_exactly_four_bytes_from_an_offset_record() {
        let record = [0xa5, 0x01, 0x23, 0x45, 0x67, 0x5a];

        assert_eq!(unsafe { rgba8_to_rgba8888(record.as_ptr().add(1)) }, 0x0123_4567);
    }

    #[test]
    fn preserves_zero_and_all_set_components() {
        assert_eq!(unsafe { rgba8_to_rgba8888([0; 4].as_ptr()) }, 0);
        assert_eq!(unsafe { rgba8_to_rgba8888([0xff; 4].as_ptr()) }, u32::MAX);
    }

    #[test]
    fn packed_equality_checks_every_channel_at_all_byte_alignments() {
        for left_offset in 0..4 {
            for right_offset in 0..4 {
                for components in [[0; 4], [0xff; 4], [0x00, 0x80, 0xff, 0x01]] {
                    let mut left = [0xa5; 8];
                    let mut right = [0x5a; 8];
                    left[left_offset..left_offset + 4].copy_from_slice(&components);
                    right[right_offset..right_offset + 4].copy_from_slice(&components);
                    let lhs = unsafe { left.as_ptr().add(left_offset) };
                    let rhs = unsafe { right.as_ptr().add(right_offset) };
                    assert_eq!(unsafe { rgba8_packed_equal(lhs, rhs) }, 1);
                    assert_eq!(unsafe { rgba8_packed_equal(lhs, lhs) }, 1);
                    for channel in 0..4 {
                        right[right_offset + channel] ^= 0x80;
                        assert_eq!(unsafe { rgba8_packed_equal(lhs, rhs) }, 0);
                        assert_eq!(unsafe { rgba8_packed_equal(rhs, lhs) }, 0);
                        right[right_offset + channel] ^= 0x80;
                    }
                }
            }
        }
    }

    #[test]
    fn packed_equality_accepts_overlapping_records() {
        let bytes = [0x80; 5];
        assert_eq!(unsafe {
            rgba8_packed_equal(bytes.as_ptr(), bytes.as_ptr().add(1))
        }, 1);
        let bytes = [0x80, 0x80, 0x80, 0x80, 0xff];
        assert_eq!(unsafe {
            rgba8_packed_equal(bytes.as_ptr(), bytes.as_ptr().add(1))
        }, 0);
    }
}
