//! `word_list_is_zero` — original: `FUN_082d72a0` @ 0x082d72a0.
//!
//! Raw extent: 68 bytes (17 ARM words), ending at 0x082d72e0; the distinct
//! successor starts at 0x082d72e4 with `mov r2, r0; push {lr}`. Decoding every
//! ARM B/BL word in `osos.dec` found five plain unconditional `bl` callers
//! (0x080ec18c, 0x082b7974, 0x082ceb1c, 0x082d3e70, 0x0836940c), no predicated
//! `bl` callers, and no calls in this leaf.
//!
//! Returns one when the counted [`WordList`] has no nonzero element among its
//! leading `count` words; an empty list is zero. The original only loads the
//! entries pointer after observing a nonzero count, so a zero-count list never
//! dereferences `entries`. No deliberate deviations.

use super::word_list::WordList;

/// Tests whether every active word in `list` is zero.
///
/// # Safety
/// When `(*list).count` is nonzero, `list` must be a valid [`WordList`] whose
/// `entries` points to at least `count` readable, aligned `u32` words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_is_zero(list: *const WordList) -> i32 {
    let count = (*list).count as usize;
    if count == 0 {
        return 1;
    }

    let entries = (*list).entries;
    for index in 0..count {
        if *entries.add(index) != 0 {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::word_list_is_zero;
    use crate::util::word_list::WordList;

    fn list(entries: &mut [u32], count: u16) -> WordList {
        WordList {
            count,
            capacity: entries.len() as u16,
            entries: entries.as_mut_ptr(),
        }
    }

    #[test]
    fn empty_list_does_not_dereference_entries() {
        let list = WordList {
            count: 0,
            capacity: 0,
            entries: core::ptr::null_mut(),
        };

        assert_eq!(unsafe { word_list_is_zero(&list) }, 1);
    }

    #[test]
    fn accepts_all_zero_active_words() {
        let mut entries = [0, 0, 0, 0];
        let list = list(&mut entries, 4);

        assert_eq!(unsafe { word_list_is_zero(&list) }, 1);
    }

    #[test]
    fn rejects_nonzero_word_at_each_active_position() {
        for nonzero_index in 0..4 {
            let mut entries = [0; 4];
            entries[nonzero_index] = 0x8000_0000;
            let list = list(&mut entries, 4);

            assert_eq!(unsafe { word_list_is_zero(&list) }, 0);
        }
    }

    #[test]
    fn ignores_words_after_count() {
        let mut entries = [0, 0, 0xdead_beef];
        let list = list(&mut entries, 2);

        assert_eq!(unsafe { word_list_is_zero(&list) }, 1);
    }
}
