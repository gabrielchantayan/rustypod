//! One-word insertion-sort helper from retailOS.
//!
//! `FUN_083e9aec` @ `0x083e9aec` is **60 bytes**
//! (`0x083e9aec..0x083e9b28`; the next real function starts at
//! `0x083e9b28`). Raw ARM decoding verifies two plain inbound `bl` call sites
//! (`0x083e83dc` and `0x083ea760`), no predicated inbound `bl` calls, no
//! outbound direct `bl` calls, and one indirect `blx r6` comparator call.
//!
//! Algorithm: starting at `slot`, compare `value` with each preceding word.
//! While the comparator returns nonzero, shift that word one position right;
//! write `value` at the first position for which it returns zero.
//!
//! No deliberate deviations.

/// Comparator ABI used by retailOS's word insertion sort.
pub type WordOrder = unsafe extern "C" fn(u32, u32) -> i32;

/// word_insertion_sort_insert — original: `FUN_083e9aec` @ `0x083e9aec`
/// (60 bytes; 2 plain inbound `bl` call sites, 0 predicated). See the module
/// header for byte-verified extent, comparator dispatch, and algorithm.
///
/// # Safety
///
/// `slot` must be within a writable word array and have at least one preceding
/// readable word. `comparator` must accept the held value followed by a prior
/// array word. The array must have a preceding comparator-zero sentinel.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn word_insertion_sort_insert(
    mut slot: *mut u32,
    value: u32,
    comparator: WordOrder,
) {
    loop {
        let prior = slot.sub(1);
        let prior_value = prior.read();
        if comparator(value, prior_value) == 0 {
            slot.write(value);
            return;
        }
        slot.write(prior_value);
        slot = prior;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn shift_if_less(value: u32, prior: u32) -> i32 {
        (value < prior) as i32
    }

    unsafe extern "C" fn shift_if_greater(value: u32, prior: u32) -> i32 {
        (value > prior) as i32
    }

    #[test]
    fn shifts_multiple_words_until_preceding_comparator_zero() {
        let mut words = [1, 3, 5, 7, 4];
        unsafe { word_insertion_sort_insert(words.as_mut_ptr().add(4), 4, shift_if_less) };
        assert_eq!(words, [1, 3, 4, 5, 7]);
    }

    #[test]
    fn stops_at_first_comparator_zero_without_shifting_equal_word() {
        let mut words = [1, 3, 3, 5, 3];
        unsafe { word_insertion_sort_insert(words.as_mut_ptr().add(4), 3, shift_if_less) };
        assert_eq!(words, [1, 3, 3, 3, 5]);
    }

    #[test]
    fn supports_reverse_ordering_callback() {
        let mut words = [9, 7, 5, 8];
        unsafe { word_insertion_sort_insert(words.as_mut_ptr().add(3), 8, shift_if_greater) };
        assert_eq!(words, [9, 8, 7, 5]);
    }
}
