//! Serializes four words into one big-endian 16-byte block.
//!
//! `store_four_u32_be` — original: `FUN_0802a158` @ **0x0802a158** (124 bytes,
//! 0x0802a158..0x0802a1d4; the separately linked next function begins at
//! 0x0802a1d4). Decoding every ARM `B`/`BL` word in `osos.dec` verifies six
//! direct inbound call sites, all plain unconditional `bl` (0x0802a224,
//! 0x0802a3d4, 0x0802a5b4, 0x0802a764, 0x0802ad84, and 0x0802adf0); there are
//! no predicated BL forms or direct tail branches.
//!
//! The fifth ARM C-ABI argument is the destination. The function stores each
//! of its four u32 arguments most-significant byte first, producing one
//! contiguous 16-byte block. It has no NULL, alignment, or bounds guard.
//! Volatile byte stores retain the firmware's high-to-low and word-to-word
//! observable store order. Deliberate deviations: none.

/// Stores four u32 values as sixteen ordered big-endian bytes.
///
/// # Safety
///
/// `destination` must be non-NULL and writable for sixteen bytes. It may have
/// any byte alignment.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.store_four_u32_be")]
#[inline(never)]
pub unsafe extern "C" fn store_four_u32_be(
    first: u32,
    second: u32,
    third: u32,
    fourth: u32,
    destination: *mut u8,
) {
    destination.write_volatile((first >> 24) as u8);
    destination.add(1).write_volatile((first >> 16) as u8);
    destination.add(2).write_volatile((first >> 8) as u8);
    destination.add(3).write_volatile(first as u8);
    destination.add(4).write_volatile((second >> 24) as u8);
    destination.add(5).write_volatile((second >> 16) as u8);
    destination.add(6).write_volatile((second >> 8) as u8);
    destination.add(7).write_volatile(second as u8);
    destination.add(8).write_volatile((third >> 24) as u8);
    destination.add(9).write_volatile((third >> 16) as u8);
    destination.add(10).write_volatile((third >> 8) as u8);
    destination.add(11).write_volatile(third as u8);
    destination.add(12).write_volatile((fourth >> 24) as u8);
    destination.add(13).write_volatile((fourth >> 16) as u8);
    destination.add(14).write_volatile((fourth >> 8) as u8);
    destination.add(15).write_volatile(fourth as u8);
}

#[cfg(test)]
mod tests {
    use super::store_four_u32_be;

    #[test]
    fn serializes_every_word_most_significant_byte_first() {
        let mut actual = [0u8; 16];

        unsafe {
            store_four_u32_be(
                0x0123_4567,
                0x89ab_cdef,
                0x8000_0001,
                u32::MAX,
                actual.as_mut_ptr(),
            );
        }

        assert_eq!(
            actual,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x80, 0x00,
                0x00, 0x01, 0xff, 0xff, 0xff, 0xff,
            ]
        );
    }

    #[test]
    fn writes_exactly_sixteen_bytes_at_every_byte_alignment() {
        let words = [0, 0x0102_0304, 0xa5a5_5a5a, u32::MAX];
        let expected_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0xa5, 0xa5,
            0x5a, 0x5a, 0xff, 0xff, 0xff, 0xff,
        ];

        for offset in 0..=7 {
            let mut actual = [0x5au8; 24];
            unsafe {
                store_four_u32_be(
                    words[0],
                    words[1],
                    words[2],
                    words[3],
                    actual.as_mut_ptr().add(offset),
                );
            }

            assert_eq!(
                &actual[offset..offset + 16],
                &expected_bytes,
                "offset={offset}"
            );
            assert!(actual[..offset].iter().all(|&byte| byte == 0x5a));
            assert!(actual[offset + 16..].iter().all(|&byte| byte == 0x5a));
        }
    }
}
