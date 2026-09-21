//! Object byte-0x4 low-bit-clear predicate — `FUN_0829d3c0` @ 0x0829d3c0
//! (16 bytes; 3 plain `bl` call sites, no predicated calls).
//!
//! Raw `osos.dec` words establish the complete function at
//! 0x0829d3c0..0x0829d3cf: `ldrb r0,[r0,#4]; mov r1,#1; bic r0,r1,r0; bx
//! lr`. The next separately linked function begins at 0x0829d3d0 with
//! `mov r0,#0; bx lr`. Decoding every aligned ARM branch word finds three
//! inbound unconditional `bl` calls at 0x0826b940, 0x0826b9a0, and
//! 0x0826ba54, with no predicated `bl` callers. It reads byte +0x4 of an
//! unchecked object pointer and returns one precisely when its low bit is
//! clear. Deliberate deviations: none.

/// Returns whether the low bit of the byte at offset +0x4 is clear.
///
/// # Safety
///
/// `object` must be valid to read at byte offset +0x4.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_byte_0x4_low_bit_is_clear")]
#[inline(never)]
pub unsafe extern "C" fn object_byte_0x4_low_bit_is_clear(object: *const u8) -> u32 {
    u32::from(object.add(4).read() & 1 == 0)
}

#[cfg(test)]
mod tests {
    use super::object_byte_0x4_low_bit_is_clear;

    #[test]
    fn returns_one_exactly_when_the_offset_0x4_low_bit_is_clear() {
        for byte in [0u8, 1, 2, 0x7e, 0x7f, 0xfe, 0xff] {
            let mut object = [0xa5u8; 5];
            object[4] = byte;

            assert_eq!(
                unsafe { object_byte_0x4_low_bit_is_clear(object.as_ptr()) },
                u32::from(byte & 1 == 0),
            );
            assert!(object[..4].iter().all(|&value| value == 0xa5));
        }
    }
}
