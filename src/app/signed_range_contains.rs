//! `signed_range_contains` — `FUN_081b6868` @ 0x081b6868.
//! True extent: 60 bytes, ending at the independent function at 0x081b68a4.
//! Raw word decoding: two inbound plain BLs (0x081a1cac, 0x081a1d24),
//! one outbound plain BL (0x081b6874), and zero predicated BLs.
//!
//! Ask the resident endpoint-validity predicate at 0x081b68a4, then return
//! exactly 0/1 for inclusive signed containment. Either endpoint equal to
//! -1 invalidates the range; reversed ranges contain nothing. Callers pass
//! the two-word range embedded at owner+0x7c and a record index in r1.
//! Deliberate deviation: host builds execute the decoded resident predicate
//! locally. ARM retains the original callee; no new callee port or NULL guard.

#[inline(always)]
unsafe fn endpoints_valid(range: *const i32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let predicate: unsafe extern "C" fn(*const i32) -> u32 =
            unsafe { core::mem::transmute(0x081b_68a4usize) };
        unsafe { predicate(range) }
    }
    #[cfg(not(target_os = "none"))]
    {
        // The raw callee skips the second load when the first word is -1.
        unsafe { (range.read_volatile() != -1 && range.add(1).read_volatile() != -1) as u32 }
    }
}

/// # Safety
/// `range` must point to two aligned readable i32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_range_contains(range: *const i32, value: i32) -> u32 {
    unsafe {
        if endpoints_valid(range) == 0 || range.read_volatile() > value {
            return 0;
        }
        (range.add(1).read_volatile() >= value) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusive_signed_bounds_and_invalid_endpoints() {
        let ranges = [
            [0, 0], [2, 7], [-8, -2], [-2, 2], [7, 2],
            [-1, 7], [-8, -1], [-1, -1], [i32::MIN, i32::MAX],
            [i32::MIN, i32::MIN], [i32::MAX, i32::MAX],
        ];
        for range in ranges {
            let before = range;
            for value in [i32::MIN, -9, -8, -2, -1, 0, 1, 2, 6, 7, 8, i32::MAX] {
                let expected = if range[0] == -1 || range[1] == -1 {
                    0
                } else if value < range[0] || value > range[1] {
                    0
                } else {
                    1
                };
                assert_eq!(unsafe { signed_range_contains(range.as_ptr(), value) }, expected,
                    "range={range:?}, value={value}");
                assert_eq!(range, before);
            }
        }
    }
}
