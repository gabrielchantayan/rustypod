//! Last byte of an opaque object's byte range.
//!
//! Original: `FUN_082a1f3c` @ `0x082a1f3c`, exactly 24 bytes through
//! `0x082a1f54`, where a distinct accessor starts with loads at +0x14/+0x18.
//! Raw words: e5901008 e590000c e1510000 15500001 03a00000 e12fff1e.
//! Whole-image A32 decoding finds two plain inbound BLs (0x0820ffc4 and
//! 0x08213ec0), zero predicated inbound BLs, and zero outbound BLs.
//!
//! Load the start and end pointer words at +0x08/+0x0c. Equal pointers
//! return zero without accessing the range; otherwise return the unsigned
//! byte immediately before end. The callers compare this byte against
//! small discriminator values; the concrete owner type is not established.
//! Target pointers remain u32 words even on hosts. Deliberate deviations:
//! none; no null checks or ordering checks are added.

/// # Safety
/// `object` must expose four aligned readable u32 words. If start != end,
/// the target-width end address minus one must point to a readable byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_byte_range_last(object: *const u32) -> u32 {
    let start = object.add(2).read();
    let end = object.add(3).read();
    if start == end {
        0
    } else {
        (end.wrapping_sub(1) as usize as *const u8).read() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_range_does_not_dereference_its_pointer() {
        for pointer in [0, 1, 0xffff_ffff] {
            let object = [0x12345678, 0x87654321, pointer, pointer];
            assert_eq!(unsafe { opaque_byte_range_last(object.as_ptr()) }, 0);
        }
    }

    #[test]
    fn returns_unsigned_last_byte_without_changing_range() {
        let Some(data) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OPAQUE_BYTE_RANGE_LAST, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("opaque_byte_range_last");
            return;
        };
        unsafe {
            for length in 1..=64 {
                for value in 0..=255u32 {
                    core::ptr::write_bytes(data, 0x5a, 66);
                    data.add(length - 1).write(value as u8);
                    let object = [0xabcdef01, 0x12345678,
                        data as usize as u32, data.add(length) as usize as u32];
                    let before = object;
                    assert_eq!(opaque_byte_range_last(object.as_ptr()), value);
                    assert_eq!(object, before);
                    assert_eq!(data.add(length).read(), 0x5a);
                    assert_eq!(data.add(65).read(), 0x5a);
                }
            }
            // The original checks equality, not ordering, and never reads start.
            data.write(0xe7);
            let object = [0, 0, u32::MAX, data.add(1) as usize as u32];
            assert_eq!(opaque_byte_range_last(object.as_ptr()), 0xe7);
        }
    }
}
