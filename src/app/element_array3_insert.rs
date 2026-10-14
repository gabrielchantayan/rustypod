//! `element_array3_insert` — `FUN_083d3a90` @ 0x083d3a90.
//! True extent: 152 bytes [0x083d3a90,0x083d3b28), ending in POP before
//! the next independent PUSH. Raw A32 scan: one inbound plain BL at
//! 0x082c8584, zero inbound predicated BLs; zero outbound plain BLs and
//! one BLEQ at 0x083d3ad8 to element_array3_expand (0x083d3b28).
//! Reject duplicate words before expanding when used equals capacity. Reload
//! capacity and storage, fill the first zero slot, increment used modulo 2^32,
//! and return its index, or -1 if no slot exists. Bounds are signed; inserting
//! zero is rejected when a hole exists. CMPGE followed by GT accepts slot zero,
//! contrary to Ghidra's C. Reuse the identical tracker insertion algorithm.
//! Deliberate deviations: LLVM may branch instead of predicate; host headers
//! retain four-byte words. No allocation-failure guard is added.

/// # Safety
/// `array` must be a writable six-word tracker header. Positive signed capacity
/// requires valid slot storage encoded in word zero as a u32 address. Expansion
/// must leave storage valid for the reloaded capacity, as in the firmware.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_array3_insert(array: *mut u32, element: u32) -> i32 {
    super::element_tracker_array_insert::insert_with(array, element, |array| {
        super::element_array3_expand::element_array3_expand(array)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::malloc_rt::{HEAP_OPS, tests::lock_ops};

    unsafe extern "C" fn relocate(storage: *mut u8, bytes: usize) -> *mut u8 {
        assert_eq!(bytes, 16);
        let destination = storage.add(32);
        core::ptr::copy_nonoverlapping(storage, destination, 8);
        destination
    }

    #[test]
    fn duplicates_holes_signed_bounds_wrap_and_real_expansion() {
        let _lock = lock_ops();
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::ELEMENT_ARRAY3_INSERT, 4096,
        ).expect("target-width array-3 storage");
        unsafe {
            let words = core::slice::from_raw_parts_mut(slab.cast::<u32>(), 16);
            for hole in 0..4 {
                words[..4].copy_from_slice(&[11, 22, 33, 44]);
                words[hole] = 0;
                let mut header = [slab as usize as u32, 4, 3, 7, 2, 9];
                assert_eq!(element_array3_insert(header.as_mut_ptr(), 55), hole as i32);
                assert_eq!(words[hole], 55);
                assert_eq!(header[2], 4);
                let before = header;
                assert_eq!(element_array3_insert(header.as_mut_ptr(), 55), -1);
                assert_eq!(header, before);
            }
            words[..4].copy_from_slice(&[11, 0, 33, 0]);
            let mut header = [slab as usize as u32, 4, u32::MAX, 7, 2, 9];
            assert_eq!(element_array3_insert(header.as_mut_ptr(), 0), -1);
            assert_eq!(header[2], u32::MAX);
            assert_eq!(element_array3_insert(header.as_mut_ptr(), 99), 1);
            assert_eq!(header[2], 0);
            words[..4].copy_from_slice(&[11, 22, 33, 44]);
            assert_eq!(element_array3_insert(header.as_mut_ptr(), 99), -1);
            for capacity in [0, 0x8000_0000, u32::MAX] {
                let mut header = [0, capacity, 1, 7, 2, 9];
                assert_eq!(element_array3_insert(header.as_mut_ptr(), 99), -1);
                assert_eq!(header, [0, capacity, 1, 7, 2, 9]);
            }
            let saved = HEAP_OPS;
            HEAP_OPS.realloc = relocate;
            words.fill(0xdead_beef);
            words[..2].copy_from_slice(&[11, 22]);
            let mut header = [slab as usize as u32, 2, 2, 7, 2, 9];
            assert_eq!(element_array3_insert(header.as_mut_ptr(), 99), 2);
            assert_eq!(header, [slab.add(32) as usize as u32, 4, 3, 7, 2, 9]);
            assert_eq!(&words[8..13], &[11, 22, 99, 0, 0xdead_beef]);
            HEAP_OPS = saved;
        }
    }
}
