//! Stable merge for the 12-byte StringObject-and-word vector records.

use super::string_object::string_object_assign;
use super::string_object_less::string_object_less;
use super::templates::{string_object_word_range_copy, StringObjectWord};

/// `string_object_word_merge` — original: `FUN_083ea788` @ `0x083ea788` (156
/// bytes; raw extent `0x083ea788..0x083ea824`, with the next separately linked
/// function opening with `push {r4-r9,sl,lr}` at `0x083ea824`). **Three
/// inbound direct `bl` call sites**, all unconditional plain `bl` at
/// `0x083e8538`, `0x083e8814`, and `0x083e882c`; no predicated `bl` forms.
/// The body contains four unconditional plain `bl` instructions and no
/// predicated `bl`: `string_object_less` once per pair, the assignment operator
/// twice (one instruction per branch), and `string_object_word_range_copy`.
/// Its final `b 0x083e9b28` is a tail branch, not a `bl`.
///
/// Stably merges sorted half-open ranges `[left, left_end)` and
/// `[right, right_end)` into initialized output storage. When the right record
/// is less than the left record it is assigned first; otherwise the left record
/// is assigned first, preserving left-before-right order for equivalent keys.
/// Once either range is exhausted, the remaining left range is copied before a
/// tail call copies the remaining right range. The returned pointer is one past
/// the final output record.
///
/// Deliberate deviations: typed record cursors replace literal `+0xc` address
/// arithmetic, preserving the ARM 12-byte layout on hosts with widened pointers.
/// The final range-copy remains a direct call to the existing port.
///
/// # Safety
///
/// Both input ranges must be sorted, readable contiguous `StringObjectWord`
/// ranges; `output` must have initialized writable capacity for both ranges.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_word_merge(
    mut left: *const StringObjectWord,
    left_end: *const StringObjectWord,
    mut right: *const StringObjectWord,
    right_end: *const StringObjectWord,
    mut output: *mut StringObjectWord,
) -> *mut StringObjectWord {
    while left != left_end && right != right_end {
        if string_object_less(
            core::ptr::null(),
            core::ptr::addr_of!((*right).string),
            core::ptr::addr_of!((*left).string),
        ) {
            string_object_assign(
                core::ptr::addr_of_mut!((*output).string),
                core::ptr::addr_of!((*right).string),
            );
            (*output).trailing_word = (*right).trailing_word;
            right = right.add(1);
        } else {
            string_object_assign(
                core::ptr::addr_of_mut!((*output).string),
                core::ptr::addr_of!((*left).string),
            );
            (*output).trailing_word = (*left).trailing_word;
            left = left.add(1);
        }
        output = output.add(1);
    }
    output = string_object_word_range_copy(left, left_end, output);
    string_object_word_range_copy(right, right_end, output)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::{
        StringObject, StringObjectAssignCstrOps, StringObjectVtable,
        DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_ASSIGN_CSTR_OPS,
    };
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;

    static mut POOL: [[u8; 8]; 8] = [[0; 8]; 8];
    static mut CURSOR: usize = 0;

    unsafe extern "C" fn allocate(this: *mut StringObject, _size: usize, _flags: u32) -> *mut u8 {
        let index = CURSOR;
        CURSOR += 1;
        let payload = core::ptr::addr_of_mut!(POOL[index]).cast();
        (*this).payload = payload;
        payload
    }

    unsafe extern "C" fn clear(_this: *mut StringObject) {}

    struct OpsGuard;
    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS) }
        }
    }

    fn assignment_fixture() -> (std::sync::MutexGuard<'static, ()>, OpsGuard) {
        let lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            CURSOR = 0;
            POOL = [[0; 8]; 8];
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear });
        }
        (lock, OpsGuard)
    }

    fn record(text: &mut [u8], trailing_word: u32) -> StringObjectWord {
        StringObjectWord { string: StringObject { vtable: 0xdead_beefusize as *const StringObjectVtable, payload: text.as_mut_ptr() }, trailing_word }
    }

    #[test]
    fn merges_stably_and_copies_both_exhaustion_tails() {
        let _fixture = assignment_fixture();
        let mut a = *b"a\0";
        let mut c_left = *b"c\0";
        let mut e = *b"e\0";
        let mut b = *b"b\0";
        let mut c_right = *b"c\0";
        let mut d = *b"d\0";
        let left = [record(&mut a, 1), record(&mut c_left, 2), record(&mut e, 3)];
        let right = [record(&mut b, 4), record(&mut c_right, 5), record(&mut d, 6)];
        let mut output = [record(&mut [], 0), record(&mut [], 0), record(&mut [], 0), record(&mut [], 0), record(&mut [], 0), record(&mut [], 0)];

        unsafe {
            assert_eq!(string_object_word_merge(left.as_ptr(), left.as_ptr().add(3), right.as_ptr(), right.as_ptr().add(3), output.as_mut_ptr()), output.as_mut_ptr().add(6));
            assert_eq!(output.map(|record| record.trailing_word), [1, 4, 2, 5, 6, 3]);
            assert_eq!(&POOL[2][..2], b"c\0", "left equivalent key precedes right key");
        }
    }
}