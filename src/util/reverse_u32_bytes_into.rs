//! Four-byte order reversal — `reverse_u32_bytes_into` @ 0x080f1524.
//!
//! Original: `FUN_080f1524` @ 0x080f1524 (48 bytes; extent verified from
//! raw `osos.dec`: the next separately linked body starts at 0x080f1554).
//! Decoding every ARM branch word confirms four direct inbound `bl` call
//! sites, and zero direct calls in this body (zero plain and zero predicated
//! `bl` instructions).
//!
//! Algorithm: copy four source bytes to the destination in reverse order,
//! reading and writing one byte per iteration. This is used by the caller to
//! decode big-endian u32 fields into little-endian stack words. Deliberate
//! deviations: a Rust loop replaces the ARM decrementing-address sequence;
//! volatile byte accesses retain the original operation order for overlapping
//! source and destination ranges.

/// reverse_u32_bytes_into — original: `FUN_080f1524` @ 0x080f1524 (48 bytes;
/// four direct inbound `bl` call sites, binary-decoded).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.reverse_u32_bytes_into")]
pub unsafe extern "C" fn reverse_u32_bytes_into(source: *const u8, destination: *mut u8) {
    for offset in 0..4 {
        let byte = unsafe { source.add(offset).read_volatile() };
        unsafe { destination.add(3 - offset).write_volatile(byte) };
    }
}

#[cfg(test)]
mod tests {
    use super::reverse_u32_bytes_into;

    #[test]
    fn reverses_four_bytes_at_every_alignment() {
        for offset in 0..4 {
            let mut actual = [0xa5; 12];
            actual[offset..offset + 4].copy_from_slice(&[0x01, 0x80, 0xfe, 0x7f]);

            unsafe {
                reverse_u32_bytes_into(actual.as_ptr().add(offset), actual.as_mut_ptr().add(offset + 4));
            }

            assert_eq!(&actual[offset + 4..offset + 8], &[0x7f, 0xfe, 0x80, 0x01]);
        }
    }

    #[test]
    fn preserves_original_bytewise_behavior_for_overlapping_ranges() {
        let mut actual = [0x10, 0x20, 0x30, 0x40];

        unsafe { reverse_u32_bytes_into(actual.as_ptr(), actual.as_mut_ptr()) };

        assert_eq!(actual, [0x10, 0x20, 0x20, 0x10]);
    }
}
