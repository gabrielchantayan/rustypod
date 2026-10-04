//! object_top_byte_flags_contains — `FUN_0821432c` @ 0x0821432c.
//! True extent: 28 bytes, ending at the next function's push at 0x08214348.
//! Whole-image A32 decoding verifies two plain inbound BL calls (0x0818b7ac,
//! 0x0818b894), zero predicated inbound BL calls, and zero outbound BL calls.
//!
//! Load the object's first aligned word, intersect it with the requested mask
//! and 0xff000000, then compare against the complete requested mask. Thus an
//! empty mask succeeds and any requested low-24-bit flag fails. Both observed
//! callers request 0x08000000; the meaning of that flag is not established.
//! No deliberate behavioral deviations; invalid pointers remain unchecked.

/// Returns exactly 0 or 1 according to whether all requested top-byte flags
/// are present. Lower bits in `mask` are rejected, not silently discarded.
///
/// # Safety
/// `object` must point to a readable, aligned u32, even when `mask` is zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_top_byte_flags_contains(object: *const u32, mask: u32) -> u32 {
    u32::from((object.read() & mask & 0xff00_0000) == mask)
}

#[cfg(test)]
mod tests {
    use super::object_top_byte_flags_contains;

    #[test]
    fn all_top_byte_subsets_match_bitwise_reference() {
        for flags in 0u32..=255 {
            for requested in 0u32..=255 {
                let mut expected = 1;
                for bit in 0..8 {
                    if requested & (1 << bit) != 0 && flags & (1 << bit) == 0 {
                        expected = 0;
                    }
                }
                for lower in [0, 0x00ab_cdef] {
                    let object = (flags << 24) | lower;
                    assert_eq!(unsafe {
                        object_top_byte_flags_contains(&object, requested << 24)
                    }, expected, "flags={flags:#x}, requested={requested:#x}");
                }
            }
        }
    }

    #[test]
    fn every_lower_mask_bit_is_rejected_even_when_present() {
        let object = u32::MAX;
        for bit in 0..24 {
            for top in [0, 0x0800_0000, 0xff00_0000] {
                assert_eq!(unsafe {
                    object_top_byte_flags_contains(&object, top | (1 << bit))
                }, 0);
            }
        }
        assert_eq!(unsafe { object_top_byte_flags_contains(&object, u32::MAX) }, 0);
    }

    #[test]
    fn caller_flag_and_empty_mask_return_canonical_booleans() {
        for (object, expected) in [(0, 0), (0x0800_0000, 1), (0xf7ff_ffff, 0), (u32::MAX, 1)] {
            assert_eq!(unsafe { object_top_byte_flags_contains(&object, 0x0800_0000) }, expected);
            assert_eq!(unsafe { object_top_byte_flags_contains(&object, 0) }, 1);
        }
    }
}
