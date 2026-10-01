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

/// `tagged_rgba8_equal` — original: `FUN_0829ff54` @ `0x0829ff54`
/// (64 bytes; 2 unconditional incoming BLs at 0x0829fc08 and 0x0829fdd0,
/// zero predicated BLs, verified by decoding raw ARM words in osos.dec).
///
/// Compares the leading tag bytes. Unequal tags return 0; equal zero tags
/// return 1 without touching the payload. Equal nonzero tags compare the
/// following four RGBA bytes via `rgba8_packed_equal` at 0x082a0124.
/// The sole outgoing BL is unconditional at 0x0829ff78. The final pop is
/// at 0x0829ff90; the next independent function starts at 0x0829ff94.
/// Deliberate deviations: none.
///
/// # Safety
///
/// Both pointers must identify a readable tag byte. If the tags are equal
/// and nonzero, each must also have four readable bytes following it.
/// Alignment is unrestricted.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_rgba8_equal")]
#[inline(never)]
pub unsafe extern "C" fn tagged_rgba8_equal(left: *const u8, right: *const u8) -> u32 {
    let left_tag = *left;
    let right_tag = *right;
    if left_tag != right_tag {
        return 0;
    }
    if left_tag == 0 {
        return 1;
    }
    u32::from(rgba8_packed_equal(left.add(1), right.add(1)) != 0)
}

#[cfg(test)]
mod tests {
    use super::{rgba8_packed_equal, rgba8_to_rgba8888, tagged_rgba8_equal};

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

    #[test]
    fn tagged_equality_short_circuits_without_a_payload() {
        let absent = [0u8];
        let present = [0xffu8];
        assert_eq!(unsafe { tagged_rgba8_equal(absent.as_ptr(), absent.as_ptr()) }, 1);
        assert_eq!(unsafe { tagged_rgba8_equal(absent.as_ptr(), present.as_ptr()) }, 0);
        assert_eq!(unsafe { tagged_rgba8_equal(present.as_ptr(), absent.as_ptr()) }, 0);
        let left = [0, 1, 2, 3, 4];
        let right = [0, 5, 6, 7, 8];
        assert_eq!(unsafe { tagged_rgba8_equal(left.as_ptr(), right.as_ptr()) }, 1);
    }

    #[test]
    fn tagged_equality_checks_tags_and_every_payload_byte() {
        for left_offset in 0..4 {
            for right_offset in 0..4 {
                for tag in [1, 0x80, 0xff] {
                    let record = [tag, 0, 0x80, 0xff, 1];
                    let mut left = [0xa5; 8];
                    let mut right = [0x5a; 8];
                    left[left_offset..left_offset + 5].copy_from_slice(&record);
                    right[right_offset..right_offset + 5].copy_from_slice(&record);
                    let lhs = unsafe { left.as_ptr().add(left_offset) };
                    let rhs = unsafe { right.as_ptr().add(right_offset) };
                    assert_eq!(unsafe { tagged_rgba8_equal(lhs, rhs) }, 1);
                    assert_eq!(unsafe { tagged_rgba8_equal(lhs, lhs) }, 1);
                    for byte in 0..5 {
                        right[right_offset + byte] ^= 0x80;
                        assert_eq!(unsafe { tagged_rgba8_equal(lhs, rhs) }, 0);
                        assert_eq!(unsafe { tagged_rgba8_equal(rhs, lhs) }, 0);
                        right[right_offset + byte] ^= 0x80;
                    }
                }
            }
        }
        let overlap = [0xff; 6];
        assert_eq!(unsafe {
            tagged_rgba8_equal(overlap.as_ptr(), overlap.as_ptr().add(1))
        }, 1);
    }
}
