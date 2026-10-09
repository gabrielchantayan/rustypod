//! entry_table_finalize_last — retailOS `FUN_080c1050` @ 0x080c1050.
//!
//! True size: 24 bytes; raw A32 words end with `bx lr` at 0x080c1064,
//! followed by a new function at 0x080c1068 (`subs ip,r0,#0x100`).
//! Whole-image word decoding finds two plain incoming BLs (0x0809c0b4,
//! 0x080cd990), zero predicated incoming BLs, and zero outgoing BLs.
//!
//! Algorithm: read the count at state word 3. If nonzero, load the target
//! pointer at word 5 and overwrite word 3 of the last 16-byte entry.
//! Deliberate deviations: none in memory behavior; incidental r0 contents
//! are not exposed by the void ABI. Pointer arithmetic wraps at target width.

/// Stores the completion value in the last entry, or does nothing if empty.
///
/// # Safety
/// `state` must contain readable aligned words through word 3. For a nonzero
/// count, word 5 must be readable and its target-width address plus
/// `count * 16 - 4` (wrapping u32 arithmetic) must identify a writable u32.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn entry_table_finalize_last(state: *mut u32, value: u32) {
    let count = unsafe { state.add(3).read() };
    if count != 0 {
        let base = unsafe { state.add(5).read() };
        let address = base.wrapping_add(count.wrapping_mul(16)).wrapping_sub(4);
        unsafe { (address as usize as *mut u32).write(value) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_does_not_read_the_data_pointer() {
        // Only four words are allocated: reading word 5 would be invalid.
        let mut state = [0x1234_5678, 2, 3, 0];
        unsafe { entry_table_finalize_last(state.as_mut_ptr(), u32::MAX) };
        assert_eq!(state, [0x1234_5678, 2, 3, 0]);
    }

    #[test]
    fn writes_only_last_entry_word_with_target_width_wrapping() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::ENTRY_TABLE_FINALIZE_LAST, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("util/entry_table_finalize_last"));
            return;
        };
        let entries = slab.cast::<u32>();
        for count in [1u32, 2, 7, 0x1000_0001] {
            for value in [0, 0x8000_0000, u32::MAX] {
                let mut state = [10, 20, 30, count, 40, entries as u32];
                let before = state;
                unsafe {
                    for i in 0..32 { entries.add(i).write(0xabcdef01); }
                    entry_table_finalize_last(state.as_mut_ptr(), value);
                    let last_word = ((count & 0x0fff_ffff) * 4 - 1) as usize;
                    for i in 0..32 {
                        assert_eq!(entries.add(i).read(), if i == last_word { value } else { 0xabcdef01 });
                    }
                }
                assert_eq!(state, before);
            }
        }
    }
}
