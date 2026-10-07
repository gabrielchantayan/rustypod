//! Tagged-descriptor predicate used by the retailOS WAVE loader.

/// `wave_has_small_tagged_descriptor` — `FUN_08136fc4` @ 0x08136fc4.
/// True extent [0x08136fc4, 0x08136ff4): 48 bytes; the next function
/// starts at 0x08136ff4. Raw ARM-word decoding verifies two plain BL
/// callers (0x08137154, 0x08207430), zero predicated BL callers, and
/// zero outgoing calls.
///
/// Read owner word one as a target-width descriptor pointer. Return one
/// only when it is not the all-ones sentinel, its first word is 0xffff0000,
/// and its second word is unsigned less than four. Otherwise return zero.
/// The WAVE validator accepts this case without parsing RIFF; its caller
/// routes it through a separate load path. The tag's deeper meaning is
/// unknown. No deliberate behavioral deviations: zero is not a sentinel,
/// and failed tag checks do not read the second descriptor word.
///
/// # Safety
/// `owner` must expose two aligned u32 words. Unless owner word one is
/// u32::MAX, it must point to a readable aligned u32; if that word equals
/// 0xffff0000, the following word must also be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wave_has_small_tagged_descriptor(owner: *const u32) -> u32 {
    let address = *owner.add(1);
    if address == u32::MAX {
        return 0;
    }
    let descriptor = address as usize as *const u32;
    if *descriptor != 0xffff_0000 {
        return 0;
    }
    (*descriptor.add(1) < 4) as u32
}

#[cfg(test)]
mod tests {
    use super::wave_has_small_tagged_descriptor;

    #[test]
    fn sentinel_exact_tag_and_unsigned_size_boundary() {
        unsafe {
            let owner = [0x1234_5678, u32::MAX];
            assert_eq!(wave_has_small_tagged_descriptor(owner.as_ptr()), 0);
            let Some(slab) = crate::testing::try_map_u32_slab(
                crate::testing::hints::WAVE_HAS_SMALL_TAGGED_DESCRIPTOR, 4096,
            ) else {
                crate::testing::note_missing_u32_fixture("util/wave_has_small_tagged_descriptor");
                return;
            };
            let descriptor = slab as *mut u32;
            let owner = [0xdead_beef, descriptor as usize as u32];
            for tag in [0, 0xffff_0001, 0xfffe_0000, u32::MAX, 0xffff_0000] {
                for size in [0, 1, 2, 3, 4, 5, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
                    *descriptor = tag;
                    *descriptor.add(1) = size;
                    let expected = match (tag, size) {
                        (0xffff_0000, 0..=3) => 1,
                        _ => 0,
                    };
                    assert_eq!(wave_has_small_tagged_descriptor(owner.as_ptr()), expected,
                        "tag={tag:#x}, size={size:#x}");
                    assert_eq!(*descriptor, tag);
                    assert_eq!(*descriptor.add(1), size);
                }
            }
            // A wrong tag at the mapping's final word needs no size word.
            let last = slab.add(4092) as *mut u32;
            *last = 0xffff_0001;
            let owner = [0, last as usize as u32];
            assert_eq!(wave_has_small_tagged_descriptor(owner.as_ptr()), 0);
        }
    }
}
