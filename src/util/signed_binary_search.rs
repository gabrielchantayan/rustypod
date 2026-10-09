//! Inclusive-bound binary search — `FUN_080edb8c` @ `0x080edb8c`.
//!
//! True extent: 100 bytes, `[0x080edb8c, 0x080edbf0)`; next entry is a
//! separate PUSH prologue. Raw scan: two incoming plain BLs (0x080dc954,
//! 0x080dc9b8), zero predicated BLs. Body: zero direct BLs, one BLX r9.
//! Starts with low=0 and high=count-1, computes the arithmetic-shifted
//! wrapping sum midpoint, and calls compare(key, element). Negative results
//! lower high, positive results raise low, equality returns the element;
//! exhausted signed bounds return NULL. Unlike ADS bsearch, duplicates select
//! the lower midpoint of the inclusive range.
//!
//! Deliberate deviation: host base pointers retain their native width; index,
//! stride multiplication and bounds remain wrapping 32-bit firmware arithmetic.

use crate::strto::strtod::BsearchCmpFn;

/// Caller must supply readable elements and a comparator valid for every
/// visited index. Wrapped/negative indices require correspondingly valid memory.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_binary_search(
    key: *const u8,
    base: *const u8,
    count: u32,
    stride: u32,
    compare: BsearchCmpFn,
) -> *mut u8 {
    let mut low = 0i32;
    let mut high = count.wrapping_sub(1) as i32;
    while low <= high {
        let midpoint = low.wrapping_add(high) >> 1;
        let offset = stride.wrapping_mul(midpoint as u32);
        let element = base.wrapping_add(offset as usize);
        let order = unsafe { compare(key, element) };
        if order < 0 {
            high = midpoint.wrapping_sub(1);
        } else if order > 0 {
            low = midpoint.wrapping_add(1);
        } else {
            return element as *mut u8;
        }
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn compare(key: *const u8, element: *const u8) -> i32 {
        let key = unsafe { key.cast::<i32>().read() };
        let value = unsafe { element.cast::<i32>().read() };
        if key < value { i32::MIN } else if key > value { i32::MAX } else { 0 }
    }

    unsafe extern "C" fn forbidden(_: *const u8, _: *const u8) -> i32 {
        panic!("empty signed range must not invoke comparator")
    }

    #[test]
    fn empty_and_negative_high_never_access_memory() {
        for count in [0, 0x8000_0001, u32::MAX] {
            assert!(unsafe { signed_binary_search(core::ptr::null(), core::ptr::null(), count, 4, forbidden) }.is_null());
        }
    }

    #[test]
    fn matches_reference_for_every_small_range_and_missing_key() {
        let records: [[i32; 3]; 33] = core::array::from_fn(|i| [i as i32 * 2 - 32, -777, 888]);
        for count in 1..=33 {
            for key in -35i32..=35 {
                let actual = unsafe { signed_binary_search((&key as *const i32).cast(), records.as_ptr().cast(), count, 12, compare) };
                let expected = records[..count as usize].iter().position(|r| r[0] == key)
                    .map_or(core::ptr::null_mut(), |i| records.as_ptr().wrapping_add(i) as *mut u8);
                assert_eq!(actual, expected, "count={count}, key={key}");
            }
        }
    }

    #[test]
    fn duplicates_use_lower_midpoint_and_zero_stride_is_allowed() {
        let records = [7i32; 6];
        let key = 7i32;
        let result = unsafe { signed_binary_search((&key as *const i32).cast(), records.as_ptr().cast(), 6, 4, compare) };
        assert_eq!(result, records.as_ptr().wrapping_add(2) as *mut u8);
        let result = unsafe { signed_binary_search((&key as *const i32).cast(), records.as_ptr().cast(), 9, 0, compare) };
        assert_eq!(result, records.as_ptr() as *mut u8);
    }
}
