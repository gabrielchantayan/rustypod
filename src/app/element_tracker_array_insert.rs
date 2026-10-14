//! `element_tracker_array_insert` — `FUN_083d52a4` @ 0x083d52a4.
//! True extent 152 bytes, [0x083d52a4,0x083d533c), ending in POP before
//! the next independent PUSH. Raw A32: one incoming plain BL at 0x081ef430,
//! no incoming predicated BLs; zero outgoing plain BLs, one BLEQ to the
//! existing element_tracker_array_expand port at 0x083d533c.
//! Reject duplicate words, expand when used equals allocated, reload capacity,
//! then insert into the first zero slot and increment used modulo 2^32.
//! Capacity comparisons are signed. Zero is a duplicate if any hole exists.
//! Ghidra misdecodes CMPGE/CMP followed by GT: slot zero is valid.
//! Deliberate deviations: LLVM may branch instead of predicate; header and
//! storage retain four-byte words on hosts. No allocation-failure guard is added.

pub(super) unsafe fn insert_with(array: *mut u32, element: u32, expand: impl FnOnce(*mut u32)) -> i32 {
    let capacity = array.add(1).read() as i32;
    let mut index = 0;
    while index < capacity {
        let storage = array.read() as usize as *mut u32;
        if storage.add(index as usize).read() == element { return -1; }
        index += 1;
    }
    if array.add(2).read() == capacity as u32 { expand(array); }
    let capacity = array.add(1).read() as i32;
    let mut index = 0;
    while index < capacity {
        let storage = array.read() as usize as *mut u32;
        if storage.add(index as usize).read() == 0 {
            array.add(2).write(array.add(2).read().wrapping_add(1));
            let storage = array.read() as usize as *mut u32;
            storage.add(index as usize).write(element);
            return index;
        }
        index += 1;
    }
    -1
}

/// # Safety
/// `array` is a writable six-word tracker header. Positive signed capacity
/// requires readable/writable slot storage. Expansion must leave valid storage
/// for the reloaded capacity, including the original firmware failure behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_tracker_array_insert(array: *mut u32, element: u32) -> i32 {
    insert_with(array, element, |array| super::element_tracker_array_expand::element_tracker_array_expand(array))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_precedence_holes_signed_bounds_and_count_wrap() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::ELEMENT_TRACKER_ARRAY_INSERT, 4096,
        ).expect("target-width tracker storage");
        unsafe {
            let words = core::slice::from_raw_parts_mut(slab.cast::<u32>(), 8);
            for hole in 0..4 {
                words[..4].copy_from_slice(&[11, 22, 33, 44]);
                words[hole] = 0;
                let mut header = [slab as usize as u32, 4, 3, 7, 2, 9];
                assert_eq!(element_tracker_array_insert(header.as_mut_ptr(), 55), hole as i32);
                assert_eq!(words[hole], 55);
                assert_eq!(header[2], 4);
                let before = header;
                assert_eq!(insert_with(header.as_mut_ptr(), 55, |_| panic!("duplicate grew")), -1);
                assert_eq!(header, before);
            }
            words[..4].copy_from_slice(&[11, 0, 33, 0]);
            let mut header = [slab as usize as u32, 4, u32::MAX, 7, 2, 9];
            assert_eq!(element_tracker_array_insert(header.as_mut_ptr(), 0), -1);
            assert_eq!(header[2], u32::MAX);
            assert_eq!(element_tracker_array_insert(header.as_mut_ptr(), 99), 1);
            assert_eq!(header[2], 0);
            words[..4].copy_from_slice(&[11, 22, 33, 44]);
            assert_eq!(element_tracker_array_insert(header.as_mut_ptr(), 99), -1);
            for capacity in [0, 0x8000_0000, u32::MAX] {
                let mut header = [0, capacity, 1, 7, 2, 9];
                assert_eq!(element_tracker_array_insert(header.as_mut_ptr(), 99), -1);
                assert_eq!(header, [0, capacity, 1, 7, 2, 9]);
            }
            let mut header = [slab as usize as u32, 2, 2, 7, 2, 9];
            words[..2].copy_from_slice(&[11, 22]);
            assert_eq!(insert_with(header.as_mut_ptr(), 99, |array| {
                let relocated = slab.cast::<u32>().add(4);
                relocated.write(11);
                relocated.add(1).write(22);
                relocated.add(2).write(0);
                array.write(relocated as usize as u32);
                array.add(1).write(3);
            }), 2);
            assert_eq!(words[6], 99);
            assert_eq!(header[2], 3);
            assert_eq!(&header[3..], &[7, 2, 9]);
        }
    }
}
