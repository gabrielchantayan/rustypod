//! Penultimate byte of an opaque object's byte range.
//!
//! Original: `FUN_082a1ee8` @ `0x082a1ee8`, true extent 84 bytes to
//! `0x082a1f3c`: 80 instruction bytes plus the zero diagnostic literal at
//! `0x082a1f38`. The next function independently loads +0x08/+0x0c.
//! Whole-image aligned A32 decoding verifies two plain inbound BLs at
//! 0x08213dd4 and 0x08223288, no predicated inbound BLs, zero plain outbound
//! BLs, and one predicated outbound BL (`blls` at 0x082a1f28 to 0x08266abc).
//!
//! Load target-width start/end words at +0x08/+0x0c and subtract modulo
//! 2^32. Return zero for unsigned length < 2, otherwise unsigned end[-2].
//! Callers compare the byte with small discriminator values; owner identity
//! remains unknown. Deliberate deviation: omit the unreachable code-9 call
//! to cxx_new_handler_dispatch: length >= 2 implies length - 2 < length,
//! so the original LS predicate can never hold. No behavioral deviations,
//! validation, or new seams; pointer fields remain four bytes wide on hosts.

/// # Safety
/// `object` must expose four aligned readable u32 words. When the wrapping
/// end-start difference is >= 2, end minus two must address a readable byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_byte_range_penultimate(object: *const u32) -> u32 {
    let start = object.add(2).read();
    let end = object.add(3).read();
    if end.wrapping_sub(start) < 2 {
        0
    } else {
        (end.wrapping_sub(2) as usize as *const u8).read() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_wrapping_ranges_do_not_access_invalid_addresses() {
        for (start, end) in [(0, 0), (1, 1), (u32::MAX, u32::MAX),
            (0, 1), (u32::MAX, 0)] {
            let object = [0x12345678, 0x87654321, start, end];
            assert_eq!(unsafe { opaque_byte_range_penultimate(object.as_ptr()) }, 0);
        }
    }

    #[test]
    fn reads_unsigned_penultimate_byte_and_preserves_range() {
        let Some(data) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OPAQUE_BYTE_RANGE_PENULTIMATE, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("opaque_byte_range_penultimate");
            return;
        };
        unsafe {
            for length in 2..=64 {
                for value in 0..=255u32 {
                    core::ptr::write_bytes(data, 0x5a, 66);
                    data.add(length - 2).write(value as u8);
                    let object = [0xabcdef01, 0x12345678,
                        data as usize as u32, data.add(length) as usize as u32];
                    let before = object;
                    assert_eq!(opaque_byte_range_penultimate(object.as_ptr()), value);
                    assert_eq!(object, before);
                    assert_eq!(data.add(length - 1).read(), 0x5a);
                    assert_eq!(data.add(length).read(), 0x5a);
                }
            }
            // Unsigned wrapping subtraction, not pointer ordering or signed length.
            data.write(0xe7);
            for start in [u32::MAX, (data as usize as u32).wrapping_add(3)] {
                let object = [0, 0, start, data.add(2) as usize as u32];
                assert_eq!(opaque_byte_range_penultimate(object.as_ptr()), 0xe7);
            }
        }
    }
}
