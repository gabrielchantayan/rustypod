//! `word_list_matches_value` — original: `FUN_080ec178` @ 0x080ec178.
//!
//! Raw extent: 68 bytes (17 ARM words), from 0x080ec178 through 0x080ec1b8;
//! the next separately entered function begins at 0x080ec1bc. The body makes
//! one unconditional `bl`, to [`word_list_is_zero`], only when `value` is
//! zero. Complete-image decoding finds five plain unconditional inbound `bl`
//! calls (0x082cb1b8, 0x082cb1d8, 0x082cb1ec, 0x082cb200, 0x082cb214), no
//! predicated inbound `bl` calls, and no direct tail branches.
//!
//! A zero value matches a list containing only zero active words. A nonzero
//! value, or a nonzero-list zero value, matches only a single-element list
//! whose sole word equals `value`. No deliberate deviations.

use super::word_list::WordList;
use super::word_list_is_zero::word_list_is_zero;

/// Tests whether `list` represents exactly `value` under the retailOS
/// zero-list rule.
///
/// # Safety
/// `list` must point to a valid [`WordList`]. When its count is nonzero, its
/// entries pointer must address at least `count` readable, aligned `u32` words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_matches_value(value: u32, list: *const WordList) -> i32 {
    if value == 0 && word_list_is_zero(list) != 0 {
        return 1;
    }

    if (*list).count == 1 && *(*list).entries == value {
        return 1;
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::word_list_matches_value;
    use crate::util::word_list::WordList;

    fn list(entries: &mut [u32], count: u16) -> WordList {
        WordList {
            count,
            capacity: entries.len() as u16,
            entries: entries.as_mut_ptr(),
        }
    }

    #[test]
    fn zero_matches_empty_list_without_entries() {
        let list = WordList {
            count: 0,
            capacity: 0,
            entries: core::ptr::null_mut(),
        };

        assert_eq!(unsafe { word_list_matches_value(0, &list) }, 1);
    }

    #[test]
    fn zero_matches_every_all_zero_active_list() {
        let mut entries = [0, 0, 0xfeed_face];
        let list = list(&mut entries, 2);

        assert_eq!(unsafe { word_list_matches_value(0, &list) }, 1);
    }

    #[test]
    fn nonzero_value_requires_matching_single_element_list() {
        let mut matching = [0x1234_5678];
        let mut different = [0x1234_5679];
        let mut multiple = [0x1234_5678, 0];

        assert_eq!(unsafe { word_list_matches_value(0x1234_5678, &list(&mut matching, 1)) }, 1);
        assert_eq!(unsafe { word_list_matches_value(0x1234_5678, &list(&mut different, 1)) }, 0);
        assert_eq!(unsafe { word_list_matches_value(0x1234_5678, &list(&mut multiple, 2)) }, 0);
    }

    #[test]
    fn zero_rejects_nonzero_single_element_list() {
        let mut entries = [1];

        assert_eq!(unsafe { word_list_matches_value(0, &list(&mut entries, 1)) }, 0);
    }
}
