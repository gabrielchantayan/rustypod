//! Backward stable merge of StringObject-and-word records.

use super::string_object_less::string_object_less;
use super::string_word_record::{string_word_record_copy_assign, string_word_record_copy_backward, StringWordRecord};

/// `string_word_record_merge_backward` — original: `FUN_083e876c` @
/// `0x083e876c`, 168 bytes (`0x083e876c..0x083e8814`); the next real
/// function begins with `push {r0-r9,lr}` at `0x083e8814`. Whole-image
/// aligned A32 decoding finds one incoming plain BL at `0x083e85c8`, no
/// predicated incoming BLs. The body has three plain BLs (comparison at
/// `0x083e87bc`, assignment at `0x083e87d4` and `0x083e87f0`), no
/// predicated BLs, and a tail B to backward-copy at `0x083e8810`.
///
/// Merge two sorted half-open ranges into initialized storage ending at
/// `result_end`, assigning highest keys first. Compare right's last key
/// with left's: take left only if right < left, otherwise take right.
/// This puts equal left keys before equal right keys in the final range.
/// Once one input is exhausted, backward-copy the remaining input and
/// return the destination start. The sixth argument is a stateless comparator;
/// raw code passes the address of its stack slot to the comparison functor.
///
/// Deliberate deviations: typed repr(C) record strides replace literal
/// 12-byte steps for widened host pointers. Pass the unused comparator value
/// directly instead of its stack-slot address; the existing comparator ignores
/// that argument. No behavioral change or new callee seam.
///
/// # Safety
/// Inputs must be sorted readable contiguous record ranges. Output must have
/// initialized writable capacity for their combined length. Overlap is allowed
/// only when descending assignments cannot overwrite unread source records.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_word_record_merge_backward(
    left: *const StringWordRecord,
    mut left_end: *const StringWordRecord,
    right: *const StringWordRecord,
    mut right_end: *const StringWordRecord,
    mut result_end: *mut StringWordRecord,
    comparator: *const u8,
) -> *mut StringWordRecord {
    while left != left_end && right != right_end {
        let left_last = left_end.sub(1);
        let right_last = right_end.sub(1);
        result_end = result_end.sub(1);
        if string_object_less(comparator, core::ptr::addr_of!((*right_last).string), core::ptr::addr_of!((*left_last).string)) {
            string_word_record_copy_assign(result_end, left_last);
            left_end = left_last;
        } else {
            string_word_record_copy_assign(result_end, right_last);
            right_end = right_last;
        }
    }
    if left == left_end {
        string_word_record_copy_backward(right, right_end, result_end)
    } else {
        string_word_record_copy_backward(left, left_end, result_end)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::string_object::{StringObject, StringObjectAssignCstrOps, DEFAULT_STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_ASSIGN_CSTR_OPS};
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;

    static mut POOL: [[u8; 8]; 16] = [[0; 8]; 16];
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
    fn record(payload: *mut u8, value: u32) -> StringWordRecord {
        StringWordRecord { string: StringObject { vtable: core::ptr::null(), payload }, value }
    }

    #[test]
    fn stable_reference_merge_covers_empty_ranges_ties_and_exhaustion() {
        let _lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _guard = OpsGuard;
        unsafe {
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear });
        }
        // Every pair of sorted sequences of up to three keys from {a,b,c}.
        let mut sequences = std::vec![std::vec![]];
        for len in 1..=3 {
            for code in 0..3usize.pow(len) {
                let mut n = code;
                let keys: std::vec::Vec<_> = (0..len).map(|_| { let k = n % 3; n /= 3; k }).collect();
                if keys.windows(2).all(|w| w[0] <= w[1]) { sequences.push(keys); }
            }
        }
        for left_keys in &sequences {
            for right_keys in &sequences {
                let mut texts = [[b'a', 0], [b'b', 0], [b'c', 0]];
                let left: std::vec::Vec<_> = left_keys.iter().enumerate().map(|(i, &k)| record(texts[k].as_mut_ptr(), i as u32)).collect();
                let right: std::vec::Vec<_> = right_keys.iter().enumerate().map(|(i, &k)| record(texts[k].as_mut_ptr(), 100 + i as u32)).collect();
                let mut expected: std::vec::Vec<_> = left_keys.iter().enumerate().map(|(i, &k)| (k, i as u32)).chain(right_keys.iter().enumerate().map(|(i, &k)| (k, 100 + i as u32))).collect();
                expected.sort_by_key(|&(k, _)| k);
                let count = expected.len();
                let mut output: std::vec::Vec<_> = (0..count + 2).map(|_| record(core::ptr::null_mut(), 999)).collect();
                unsafe {
                    CURSOR = 0;
                    let start = output.as_mut_ptr().add(1);
                    let returned = string_word_record_merge_backward(left.as_ptr(), left.as_ptr().add(left.len()), right.as_ptr(), right.as_ptr().add(right.len()), start.add(count), core::ptr::null());
                    assert_eq!(returned, start);
                    for (actual, &(key, value)) in output[1..count + 1].iter().zip(&expected) {
                        assert_eq!(actual.value, value);
                        assert_eq!(*actual.string.payload, b'a' + key as u8);
                        assert_eq!(*actual.string.payload.add(1), 0);
                    }
                    assert_eq!(output[0].value, 999);
                    assert_eq!(output[count + 1].value, 999);
                    assert!(output[0].string.payload.is_null());
                    assert!(output[count + 1].string.payload.is_null());
                }
            }
        }
    }

    #[test]
    fn overlapping_left_range_and_null_empty_bounds() {
        let _lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _guard = OpsGuard;
        unsafe {
            core::ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear });
            CURSOR = 0;
            let mut a = *b"a\0";
            let mut c = *b"c\0";
            let mut b = *b"b\0";
            let mut c_right = *b"c\0";
            let mut output = [record(a.as_mut_ptr(), 1), record(c.as_mut_ptr(), 2), record(core::ptr::null_mut(), 0), record(core::ptr::null_mut(), 0)];
            let right = [record(b.as_mut_ptr(), 3), record(c_right.as_mut_ptr(), 4)];
            let start = output.as_mut_ptr();
            assert_eq!(string_word_record_merge_backward(start, start.add(2), right.as_ptr(), right.as_ptr().add(2), start.add(4), core::ptr::null()), start);
            assert_eq!(output.map(|r| r.value), [1, 3, 2, 4]);
            assert!(string_word_record_merge_backward(core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null_mut(), core::ptr::null()).is_null());
        }
    }
}
