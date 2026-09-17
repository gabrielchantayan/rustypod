//! `word_list_assign_value` — original: `FUN_082d6c6c` @ 0x082d6c6c.
//!
//! Raw extent: 36 bytes (nine ARM words), from 0x082d6c6c through
//! 0x082d6c8c; the next separately linked function starts with `push {r4,lr}`
//! at 0x082d6c90. Complete-image ARM branch decoding finds four inbound plain
//! unconditional `bl` calls (0x082cb464, 0x082cddf0, 0x082cde40, 0x08369384)
//! and no predicated `bl` calls.
//!
//! Clears the list count, then unconditionally writes `value` into the first
//! entry. A zero value leaves the list empty and returns zero; a nonzero value
//! makes the sole entry active and returns one. Capacity and later entries are
//! untouched. Deliberate deviation: none.

use super::word_list::WordList;

/// Assigns the one-word representation of `value` to `list`.
///
/// # Safety
/// `list` must point to a valid [`WordList`] whose `entries` pointer is
/// writable for one aligned `u32`, even when `value` is zero. The original
/// dereferences that pointer on both paths and does not check capacity.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_assign_value(value: u32, list: *mut WordList) -> i32 {
    let count = core::ptr::addr_of_mut!((*list).count);
    let entries = (*list).entries;
    count.write_volatile(0);
    if value != 0 {
        entries.write_volatile(value);
        count.write_volatile(1);
        1
    } else {
        entries.write_volatile(0);
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::word_list_assign_value;
    use crate::util::word_list::WordList;

    #[test]
    fn zero_clears_count_and_first_entry_but_preserves_header_and_tail() {
        let mut entries = [0xfeed_face, 0xcafe_babe];
        let mut list = WordList {
            count: 2,
            capacity: 9,
            entries: entries.as_mut_ptr(),
        };

        assert_eq!(unsafe { word_list_assign_value(0, &mut list) }, 0);
        assert_eq!(list.count, 0);
        assert_eq!(list.capacity, 9);
        assert_eq!(entries, [0, 0xcafe_babe]);
    }

    #[test]
    fn nonzero_makes_exactly_one_entry_active() {
        let mut entries = [0, 0xfeed_face];
        let mut list = WordList {
            count: 0,
            capacity: 2,
            entries: entries.as_mut_ptr(),
        };

        assert_eq!(unsafe { word_list_assign_value(0x1234_5678, &mut list) }, 1);
        assert_eq!(list.count, 1);
        assert_eq!(list.capacity, 2);
        assert_eq!(entries, [0x1234_5678, 0xfeed_face]);
    }
}
