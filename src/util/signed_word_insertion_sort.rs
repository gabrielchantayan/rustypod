//! Signed ascending word insertion sort — retailOS `FUN_080776b0`.
//!
//! Raw A32 verifies [0x080776b0, 0x080776fc), 76 bytes; the next function
//! compares object fields at +4. Zero outgoing plain/predicated BLs; two
//! incoming plain BLs at 0x080db4a0 and 0x080db4ac, zero predicated BLs.
//! For each index starting at one, swap adjacent signed words backwards
//! until the current word is strictly greater than its predecessor or the
//! start is reached. Equal words are swapped too. Callers sort coordinate
//! arrays before selecting their medians. No deliberate algorithm or ABI
//! deviations; native pointers permit the same word indexing on the host.

/// Sort `count` signed words in place in ascending order.
///
/// # Safety
/// For `count >= 2`, `words` must reference `count` aligned, readable and
/// writable i32 values. Counts zero and one do not access the pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_word_insertion_sort(count: u32, words: *mut i32) {
    let mut index = 1;
    while index < count {
        let mut cursor = index;
        while cursor != 0 {
            let previous = words.add((cursor - 1) as usize);
            let current = words.add(cursor as usize);
            let left = previous.read();
            let right = current.read();
            if right > left {
                break;
            }
            current.write(left);
            previous.write(right);
            cursor -= 1;
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::signed_word_insertion_sort;

    #[test]
    fn zero_and_one_never_dereference_the_pointer() {
        unsafe {
            signed_word_insertion_sort(0, core::ptr::null_mut());
            signed_word_insertion_sort(1, core::ptr::null_mut());
        }
    }

    #[test]
    fn exhaustive_short_arrays_preserve_boundaries_and_signed_order() {
        let alphabet = [i32::MIN, -1, 0, 1, i32::MAX];
        for count in 0..=6usize {
            for mut encoding in 0..5usize.pow(count as u32) {
                let mut storage = [0x12345678; 8];
                for word in &mut storage[1..1 + count] {
                    *word = alphabet[encoding % 5];
                    encoding /= 5;
                }
                let mut expected = storage;
                expected[1..1 + count].sort_unstable();
                unsafe { signed_word_insertion_sort(count as u32, storage.as_mut_ptr().add(1)) };
                assert_eq!(storage, expected, "count={count}");
            }
        }
    }

    #[test]
    fn long_sorted_reverse_and_duplicate_runs() {
        for pattern in 0..3 {
            let mut words = [0i32; 64];
            for (index, word) in words.iter_mut().enumerate() {
                *word = match pattern {
                    0 => index as i32 - 32,
                    1 => 32 - index as i32,
                    _ => (index % 3) as i32 - 1,
                };
            }
            let mut expected = words;
            expected.sort_unstable();
            unsafe { signed_word_insertion_sort(words.len() as u32, words.as_mut_ptr()) };
            assert_eq!(words, expected);
        }
    }
}
