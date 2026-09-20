/// strided_record_remove_selector — original: `FUN_08376b8c` @ 0x08376b8c (104 bytes).
///
/// Removes the first four-word record whose selector word matches `selector` from
/// the fixed-stride record array beginning at `owner + 0x60`. A negative selector
/// clears both counters at `+0x58` and `+0x5c`. Otherwise the last live record is
/// copied into the removed slot and both counters become the decremented count.
///
/// Raw `osos.dec` establishes the exact extent: 26 ARM words from `push {r4,r5,lr}`
/// through `pop {r4,r5,pc}`, followed by a new `push` at 0x08376bf4. The body has
/// no outbound `bl` calls. The recovered direct call sites are plain `bl`; there
/// are no predicated `bl` calls. Deliberate deviations: none.
///
/// # Safety
///
/// `owner` must address readable and writable words through the header at `+0x5c`.
/// For a nonnegative selector, its count word at `+0x58` records the number of
/// readable and writable four-word records beginning at `+0x60`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn strided_record_remove_selector(owner: *mut u32, selector: i32) {
    if selector < 0 {
        unsafe {
            owner.add(0x16).write(0);
            owner.add(0x17).write(0);
        }
        return;
    }

    let mut index = 0;
    while index < unsafe { owner.add(0x16).read() } {
        let record = unsafe { owner.add(0x18 + index as usize * 4) };
        if unsafe { record.read() } == selector as u32 {
            let count = unsafe { owner.add(0x16).read() - 1 };
            unsafe { owner.add(0x16).write(count) };

            let last_record = unsafe { owner.add(0x18 + count as usize * 4) };
            unsafe {
                record.write(last_record.read());
                record.add(1).write(last_record.add(1).read());
                record.add(2).write(last_record.add(2).read());
                record.add(3).write(last_record.add(3).read());
                owner.add(0x17).write(count);
            }
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(owner: &mut [u32; 36], index: usize, values: [u32; 4]) {
        owner[0x18 + index * 4..0x1c + index * 4].copy_from_slice(&values);
    }

    #[test]
    fn negative_selector_clears_both_counters_without_touching_records() {
        let mut owner = [0u32; 36];
        owner[0x16] = 2;
        owner[0x17] = 9;
        record(&mut owner, 0, [4, 5, 6, 7]);

        unsafe { strided_record_remove_selector(owner.as_mut_ptr(), -1) };

        assert_eq!(owner[0x16], 0);
        assert_eq!(owner[0x17], 0);
        assert_eq!(&owner[0x18..0x1c], &[4, 5, 6, 7]);
    }

    #[test]
    fn removes_matching_record_by_copying_last_record_into_its_slot() {
        let mut owner = [0u32; 36];
        owner[0x16] = 3;
        owner[0x17] = 3;
        record(&mut owner, 0, [10, 11, 12, 13]);
        record(&mut owner, 1, [20, 21, 22, 23]);
        record(&mut owner, 2, [30, 31, 32, 33]);

        unsafe { strided_record_remove_selector(owner.as_mut_ptr(), 20) };

        assert_eq!(owner[0x16], 2);
        assert_eq!(owner[0x17], 2);
        assert_eq!(&owner[0x1c..0x20], &[30, 31, 32, 33]);
    }

    #[test]
    fn skips_the_swapped_record_after_a_removal_like_the_arm_loop() {
        let mut owner = [0u32; 36];
        owner[0x16] = 3;
        owner[0x17] = 3;
        record(&mut owner, 0, [7, 1, 1, 1]);
        record(&mut owner, 1, [8, 2, 2, 2]);
        record(&mut owner, 2, [7, 3, 3, 3]);

        unsafe { strided_record_remove_selector(owner.as_mut_ptr(), 7) };

        assert_eq!(owner[0x16], 2);
        assert_eq!(owner[0x17], 2);
        assert_eq!(&owner[0x18..0x1c], &[7, 3, 3, 3]);
    }
}
