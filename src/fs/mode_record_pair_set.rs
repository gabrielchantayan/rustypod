//! Mode-selected two-word record setter at retailOS 0x0814d91c.
//!
//! Raw A32 extent [0x0814d91c, 0x0814d944): 40 bytes, ten instructions,
//! no literals; the next function begins with its own PUSH and record loop.
//! Two incoming plain BLs at 0x0813a394 and 0x0813a720, zero predicated
//! incoming BLs; zero outgoing plain or predicated BLs.
//! Mode 5 stores the input pair in context words 0 and 1; mode 6 stores it
//! in words 2 and 3. Both return zero. All other modes return 0x17 without
//! accessing context. The callers pass the subobject at parent +0x04 and
//! select modes 5 and 6 after successful virtual operations.
//! Deviations: none. Word indexing preserves target offsets on hosts;
//! no field interpretation beyond the verified pair selection is assumed.

/// Store a pair into the record selected by mode 5 or 6.
///
/// # Safety
/// For mode 5, `context` must permit aligned writes of words 0 and 1.
/// For mode 6, it must permit aligned writes of words 2 and 3.
/// Other modes do not require a valid pointer. No words are read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mode_record_pair_set(context: *mut u32, mode: u32, first: u32, second: u32) -> u32 {
    match mode {
        5 => {
            context.write(first);
            context.add(1).write(second);
        }
        6 => {
            context.add(2).write(first);
            context.add(3).write(second);
        }
        _ => return 0x17,
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_pair_matches_reference_and_preserves_surrounding_words() {
        let values = [0, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX];
        for mode in [5, 6] {
            for first in values {
                for second in values {
                    let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333,
                                     0x4444_4444, 0x5555_5555, 0x6666_6666];
                    let mut expected = words;
                    let selected = if mode == 5 { 1 } else { 3 };
                    expected[selected..selected + 2].copy_from_slice(&[first, second]);
                    assert_eq!(unsafe { mode_record_pair_set(words.as_mut_ptr().add(1), mode, first, second) }, 0);
                    assert_eq!(words, expected);
                }
            }
        }
    }

    #[test]
    fn rejected_modes_return_error_without_accessing_context() {
        for mode in [0, 1, 4, 7, 0x8000_0005, 0x8000_0006, u32::MAX] {
            let mut words = [1, 2, 3, 4];
            assert_eq!(unsafe { mode_record_pair_set(words.as_mut_ptr(), mode, 0, u32::MAX) }, 0x17);
            assert_eq!(words, [1, 2, 3, 4]);
            assert_eq!(unsafe { mode_record_pair_set(core::ptr::null_mut(), mode, u32::MAX, 0) }, 0x17);
        }
    }

    #[test]
    fn successive_modes_update_independent_pairs() {
        let mut words = [0; 4];
        unsafe {
            assert_eq!(mode_record_pair_set(words.as_mut_ptr(), 6, 30, 40), 0);
            assert_eq!(mode_record_pair_set(words.as_mut_ptr(), 5, 10, 20), 0);
            assert_eq!(mode_record_pair_set(words.as_mut_ptr(), 6, 50, 60), 0);
        }
        assert_eq!(words, [10, 20, 50, 60]);
    }
}
