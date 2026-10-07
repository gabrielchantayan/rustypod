//! Translate logical extent pairs to backend block ranges.
//!
//! `storage_extents_translate` — `FUN_08136d80` @ load address 0x08136d80.
//! True size: 80 bytes, [0x08136d80, 0x08136dd0); the next function starts
//! with push {r4-r8,lr}. Raw aligned A32 branch decoding verifies two incoming
//! plain BLs (0x08136994, 0x08136f18), zero predicated incoming BLs, and one
//! outgoing plain BL (0x08136db0 -> 0x08161e48), zero predicated outgoing BLs.
//!
//! Visit at most eight two-word extents at object+0x3c, stopping before the
//! first zero start word. The helper uses backend+0x10's block base (+0x3c0)
//! and scale (+0x3c4) to translate each pair into the array pointed to by
//! object+0x9c. Increment object+0xe0 after every helper call; do not reset it.
//!
//! Deliberate deviation: the unported, raw-verified pair translator at
//! 0x08161e48 remains a direct address seam on ARM. Host execution uses its
//! exact wrapping arithmetic and load/store order, not a recorder. Target
//! pointer fields stay u32 on every platform. No target behavioral deviation.

use core::ptr::{read_volatile, write_volatile};

#[inline(always)]
unsafe fn translate_extent(backend: *mut u32, source: *const u32, output: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let translate: unsafe extern "C" fn(*mut u32, *const u32, *mut u32) =
            core::mem::transmute(0x0816_1e48usize);
        translate(backend, source, output);
    }
    #[cfg(not(target_os = "none"))]
    {
        // Raw helper: base and scale are loaded before storing the start;
        // length and scale are reloaded afterwards (including alias effects).
        let base = read_volatile(backend.add(0x3c0 / 4));
        let start = read_volatile(source);
        let scale = read_volatile(backend.add(0x3c4 / 4));
        write_volatile(output, start.wrapping_mul(scale).wrapping_add(base));
        let length = read_volatile(source.add(1));
        let scale = read_volatile(backend.add(0x3c4 / 4));
        write_volatile(output.add(1), length.wrapping_mul(scale));
    }
}

/// # Safety
/// `extents` must expose aligned writable firmware words through +0xe0.
/// For each nonzero input start, +4 must point to a backend readable through
/// +0x3d4 and +0x9c to storage for the corresponding translated pair. The
/// original does not validate pointers, bounds, scales, or the existing count.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn storage_extents_translate(extents: *mut u32) {
    for index in 0..8 {
        let source = extents.add(0x3c / 4 + index * 2);
        if read_volatile(source) == 0 {
            return;
        }
        let output_address = read_volatile(extents.add(0x9c / 4));
        let backend_address = read_volatile(extents.add(1));
        let output = output_address.wrapping_add((index * 8) as u32) as usize as *mut u32;
        let backend = backend_address.wrapping_add(0x10) as usize as *mut u32;
        translate_extent(backend, source, output);
        let count = extents.add(0xe0 / 4);
        write_volatile(count, read_volatile(count).wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_prefixes_bounds_wrapping_and_in_place_pairs() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::STORAGE_EXTENTS_TRANSLATE, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("fs/storage_extents_translate"));
            return;
        };
        unsafe {
            let object = slab as *mut u32;
            let backend = slab.add(0x200) as *mut u32;
            let separate_output = slab.add(0x800) as *mut u32;
            // Empty input must not dereference either null pointer field.
            core::ptr::write_bytes(slab, 0, 0x1000);
            *object.add(0xe0 / 4) = 37;
            storage_extents_translate(object);
            assert_eq!(*object.add(0xe0 / 4), 37);

            for in_place in [false, true] {
                for prefix in 0..=8 {
                    for (base, scale) in [(17u32, 3u32), (u32::MAX, u32::MAX), (42, 0)] {
                        core::ptr::write_bytes(slab, 0, 0x1000);
                        let source = object.add(0x3c / 4);
                        let output = if in_place { source } else { separate_output };
                        *object.add(1) = backend as usize as u32;
                        *object.add(0x9c / 4) = output as usize as u32;
                        *object.add(0xe0 / 4) = u32::MAX - 3;
                        *backend.add(0x3d0 / 4) = base;
                        *backend.add(0x3d4 / 4) = scale;
                        let mut starts = [0u32; 8];
                        let mut lengths = [0u32; 8];
                        for i in 0..8 {
                            starts[i] = if i == prefix { 0 } else { 0xffff_ff00 + i as u32 };
                            lengths[i] = if i % 2 == 0 { 0 } else { u32::MAX };
                            *source.add(i * 2) = starts[i];
                            *source.add(i * 2 + 1) = lengths[i];
                            if !in_place {
                                *output.add(i * 2) = 0xdead_beef;
                                *output.add(i * 2 + 1) = 0x1234_5678;
                            }
                        }
                        *output.add(16) = 0x8765_4321;
                        storage_extents_translate(object);
                        assert_eq!(*object.add(0xe0 / 4), (u32::MAX - 3).wrapping_add(prefix as u32));
                        for i in 0..8 {
                            let expected = if i < prefix {
                                (starts[i].wrapping_mul(scale).wrapping_add(base), lengths[i].wrapping_mul(scale))
                            } else if in_place {
                                (starts[i], lengths[i])
                            } else {
                                (0xdead_beef, 0x1234_5678)
                            };
                            assert_eq!((*output.add(i * 2), *output.add(i * 2 + 1)), expected);
                            if !in_place {
                                assert_eq!((*source.add(i * 2), *source.add(i * 2 + 1)), (starts[i], lengths[i]));
                            }
                        }
                        assert_eq!(*output.add(16), 0x8765_4321);
                    }
                }
            }
        }
    }
}
