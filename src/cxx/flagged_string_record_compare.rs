//! Compare flagged string records by flag ascending, then trailing word descending.
//!
//! Original: `FUN_081b0184` @ 0x081b0184, 60 bytes, extent
//! [0x081b0184, 0x081b01c0). The next function starts with push {r4,lr}
//! and calls this comparator after copy-constructing a temporary record.
//! Raw A32 decoding verifies two inbound plain BLs (0x081b01dc,
//! 0x083d63a0), zero inbound predicated BLs, and zero outbound BLs.
//!
//! Compare unsigned bytes at +0; only on equality compare unsigned words
//! at +0x10 in reverse order. Return exactly -1, 0, or 1. The opaque word,
//! string, and padding do not participate. No NULL guard or string access.
//! Deliberate deviation: reuse FlaggedStringRecord's repr(C) layout, whose
//! trailing word moves on hosts as embedded string pointers widen. Field
//! meanings beyond the existing flag/trailing-word names remain unknown.

use crate::cxx::flagged_string_record_copy_construct::FlaggedStringRecord;

/// Safety: both pointers must have readable flag fields and, if flags match,
/// readable aligned trailing_word fields in the FlaggedStringRecord layout.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn flagged_string_record_compare(
    left: *const FlaggedStringRecord,
    right: *const FlaggedStringRecord,
) -> i32 {
    if (*left).flag < (*right).flag {
        return -1;
    }
    if (*left).flag > (*right).flag {
        return 1;
    }
    if (*left).trailing_word > (*right).trailing_word {
        -1
    } else if (*left).trailing_word < (*right).trailing_word {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::StringObject;

    fn record(flag: u8, trailing_word: u32, noise: u32) -> FlaggedStringRecord {
        FlaggedStringRecord {
            flag,
            padding: [noise as u8; 3],
            opaque_word: noise,
            string: StringObject {
                vtable: core::ptr::null(),
                payload: core::ptr::null_mut(),
            },
            trailing_word,
        }
    }

    #[test]
    fn unsigned_ordering_and_flag_precedence_match_reference() {
        let flags = [0u8, 1, 0x7f, 0x80, 0xfe, 0xff];
        let words = [0u32, 1, 0x7fffffff, 0x80000000, u32::MAX];
        for left_flag in flags {
            for right_flag in flags {
                for left_word in words {
                    for right_word in words {
                        let left = record(left_flag, left_word, 0x12345678);
                        let right = record(right_flag, right_word, 0xffffffff);
                        let expected = match (left_flag, core::cmp::Reverse(left_word))
                            .cmp(&(right_flag, core::cmp::Reverse(right_word))) {
                            core::cmp::Ordering::Less => -1,
                            core::cmp::Ordering::Equal => 0,
                            core::cmp::Ordering::Greater => 1,
                        };
                        assert_eq!(unsafe { flagged_string_record_compare(&left, &right) }, expected);
                    }
                }
            }
        }
    }

    #[test]
    fn self_comparison_and_equal_keys_ignore_other_fields() {
        let left = record(0x80, 0x80000000, 0);
        let mut right = record(0x80, 0x80000000, u32::MAX);
        // Invalid string pointers are deliberate: comparing records must not
        // dereference or compare the embedded string.
        right.string.payload = core::ptr::dangling_mut::<u8>();
        assert_eq!(unsafe { flagged_string_record_compare(&left, &left) }, 0);
        assert_eq!(unsafe { flagged_string_record_compare(&left, &right) }, 0);
        assert_eq!(unsafe { flagged_string_record_compare(&right, &left) }, 0);
    }
}
