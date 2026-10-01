//! `record_priority_is_greater` — `FUN_082a1d1c` @ `0x082a1d1c`.
//! True extent: 64 bytes, `0x082a1d1c..0x082a1d5c`; the next function
//! starts with `ldrb r0,[r0,#16]`. Raw A32 decoding finds zero plain or
//! predicated body BLs, and two plain inbound BLs (0x083e7dc4, 0x083e7ee8),
//! with zero predicated inbound BLs.
//!
//! Returns 1 iff left is lexicographically greater than right: compare the
//! unsigned word at +0x1c first, then the signed word at +0x20 on equality.
//! Context is ignored. Deliberate deviation: express the branch/eor sequence
//! as a boolean comparison; aligned u32 indexing preserves target offsets.

/// # Safety
/// Both records must have readable, aligned words at +0x1c and +0x20.
/// `context` is never dereferenced and may be null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_priority_is_greater(
    _context: *const u8,
    left: *const u32,
    right: *const u32,
) -> u32 {
    let left_priority = unsafe { left.add(7).read() };
    let right_priority = unsafe { right.add(7).read() };
    u32::from(left_priority > right_priority
        || (left_priority == right_priority
            && unsafe { left.add(8).read() as i32 > right.add(8).read() as i32 }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_lexicographic_order_at_signed_and_unsigned_boundaries() {
        let priorities = [0, 1, i32::MAX as u32, 0x8000_0000, u32::MAX];
        let ties = [i32::MIN, -1, 0, 1, i32::MAX];
        for a in priorities {
            for b in priorities {
                for x in ties {
                    for y in ties {
                        let mut left = [0xdead_beef; 9];
                        let mut right = [0x1234_5678; 9];
                        left[7] = a;
                        left[8] = x as u32;
                        right[7] = b;
                        right[8] = y as u32;
                        let expected = u32::from((a, x) > (b, y));
                        assert_eq!(unsafe { record_priority_is_greater(core::ptr::null(), left.as_ptr(), right.as_ptr()) }, expected);
                        assert_eq!(unsafe { record_priority_is_greater(core::ptr::null(), left.as_ptr(), left.as_ptr()) }, 0);
                    }
                }
            }
        }
    }
}
