//! `word_array_remove_prefix` — original: `FUN_0808fc38` @ `0x0808fc38`
//! (92 bytes; zero plain or predicated `bl` instructions in its body).
//!
//! The next separately entered function begins at `0x0808fc94`, establishing
//! the raw extent `0x0808fc38..0x0808fc94`. The routine leaves a null or empty
//! array alone. Otherwise it shifts elements from `index` to the front and
//! reduces the count at word offset two; an index at or beyond the count clears
//! that count. The original has no callees and uses aligned word loads/stores.
//! Rust deliberately uses volatile word accesses so LLVM cannot substitute the
//! overlap-safe forward shift with an external memory routine.

use core::ptr;

const ENTRIES_WORD: usize = 0;
const COUNT_WORD: usize = 2;

/// Removes the first `index` words from an opaque counted word array.
///
/// # Safety
///
/// `array` must either be null or point to at least three writable `u32` words.
/// When its count word is nonzero and exceeds `index`, the target-width pointer
/// stored in word zero must address that many readable/writable `u32` entries.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_array_remove_prefix")]
pub unsafe extern "C" fn word_array_remove_prefix(array: *mut u32, index: u32) {
    if array.is_null() {
        return;
    }

    let count = ptr::read_volatile(array.add(COUNT_WORD));
    if count == 0 || index == 0 {
        return;
    }

    if index >= count {
        ptr::write_volatile(array.add(COUNT_WORD), 0);
        return;
    }

    let entries = ptr::read_volatile(array.add(ENTRIES_WORD)) as usize as *mut u32;
    let remaining = count - index;
    let mut source_index = index;
    let mut destination_index = 0;
    while source_index < count {
        let entry = ptr::read_volatile(entries.add(source_index as usize));
        ptr::write_volatile(entries.add(destination_index), entry);
        source_index += 1;
        destination_index += 1;
    }
    ptr::write_volatile(array.add(COUNT_WORD), remaining);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    const HEADER_WORDS: usize = 3;
    const ENTRIES_WORD_OFFSET: usize = HEADER_WORDS;

    fn fixture() -> Option<*mut u32> {
        let slab = try_map_u32_slab(hints::WORD_ARRAY_REMOVE_PREFIX, 0x1000)?;
        unsafe {
            slab.write_bytes(0, 0x1000);
            let words = slab.cast::<u32>();
            words.add(ENTRIES_WORD).write(words.add(ENTRIES_WORD_OFFSET) as usize as u32);
            Some(words)
        }
    }

    #[test]
    fn shifts_remaining_words_and_updates_count() {
        let Some(array) = fixture() else { return };
        unsafe {
            let entries = array.add(ENTRIES_WORD_OFFSET);
            entries.add(0).write(11);
            entries.add(1).write(22);
            entries.add(2).write(33);
            entries.add(3).write(44);
            array.add(COUNT_WORD).write(4);

            word_array_remove_prefix(array, 2);

            assert_eq!(array.add(COUNT_WORD).read(), 2);
            assert_eq!(entries.add(0).read(), 33);
            assert_eq!(entries.add(1).read(), 44);
        }
    }

    #[test]
    fn preserves_nonempty_array_for_zero_index_and_clears_at_end() {
        let Some(array) = fixture() else { return };
        unsafe {
            let entries = array.add(ENTRIES_WORD_OFFSET);
            entries.add(0).write(7);
            entries.add(1).write(9);
            array.add(COUNT_WORD).write(2);

            word_array_remove_prefix(array, 0);
            assert_eq!(array.add(COUNT_WORD).read(), 2);
            assert_eq!([entries.read(), entries.add(1).read()], [7, 9]);

            word_array_remove_prefix(array, 2);
            assert_eq!(array.add(COUNT_WORD).read(), 0);
            assert_eq!([entries.read(), entries.add(1).read()], [7, 9]);
        }
    }

    #[test]
    fn leaves_null_and_empty_arrays_untouched() {
        unsafe {
            word_array_remove_prefix(core::ptr::null_mut(), 1);
        }

        let Some(array) = fixture() else { return };
        unsafe {
            array.add(COUNT_WORD).write(0);
            word_array_remove_prefix(array, 99);
            assert_eq!(array.add(COUNT_WORD).read(), 0);
        }
    }
}
