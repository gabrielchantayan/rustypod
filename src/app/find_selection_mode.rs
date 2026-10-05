//! First matching selection-mode record — `FUN_081e5100` @ `0x081e5100`.
//!
//! True size: 76 bytes, ending before the next prologue at `0x081e514c`.
//! Raw A32 words contain zero plain or predicated outbound BL instructions.
//! Two inbound BL calls (`0x081e43b8`, `0x081e5798`) are unconditional;
//! there are no predicated inbound BL calls.
//!
//! Snapshot the signed count at state +0x1080, then scan byte mode fields at
//! +0x128e with stride 0x50. Write the first matching index and return zero;
//! return 3 without touching output when no record matches. Compare the byte
//! against the full u32 argument, without truncation. No behavioral deviations.

/// # Safety
/// `state` must provide an aligned readable count word at +0x1080 and readable
/// mode bytes for every positive-count record. On success, `index` must be an
/// aligned writable u32 pointer; it may alias state, as in the stock caller.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn find_selection_mode(
    state: *mut u8,
    mode: u32,
    index: *mut u32,
) -> u32 {
    let count = unsafe { state.add(0x1080).cast::<i32>().read() };
    let mut record = 0i32;
    while record < count {
        let candidate = unsafe { state.add(0x128e + record as usize * 0x50).read() };
        if u32::from(candidate) == mode {
            unsafe { index.write(record as u32) };
            return 0;
        }
        record += 1;
    }
    3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_empty_counts_do_not_access_records_or_output() {
        let mut state = [0u32; 0x1084 / 4];
        for count in [i32::MIN, -1, 0] {
            state[0x1080 / 4] = count as u32;
            assert_eq!(unsafe {
                find_selection_mode(state.as_mut_ptr().cast(), 0, core::ptr::null_mut())
            }, 3);
        }
    }

    #[test]
    fn first_match_full_width_mode_and_count_boundary() {
        let mut state = [0u32; 0x1400 / 4];
        state[0x1080 / 4] = 4;
        let bytes = state.as_mut_ptr().cast::<u8>();
        for (record, mode) in [7u8, 255, 7, 0, 9].into_iter().enumerate() {
            unsafe { bytes.add(0x128e + record * 0x50).write(mode) };
        }
        for (mode, expected) in [(7, Some(0)), (255, Some(1)), (0, Some(3)),
                                 (9, None), (256, None), (0x107, None), (u32::MAX, None)] {
            let mut output = 0xdeadbeef;
            let result = unsafe { find_selection_mode(bytes, mode, &mut output) };
            assert_eq!(result, if expected.is_some() { 0 } else { 3 });
            assert_eq!(output, expected.unwrap_or(0xdeadbeef));
        }
        assert_eq!(unsafe { find_selection_mode(bytes, 255, bytes.add(0x1078).cast()) }, 0);
        assert_eq!(state[0x1078 / 4], 1);
    }
}
