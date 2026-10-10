//! Unique signed insertion into a backward-growing array @ `0x0807f3e8`.
//!
//! True size 144 bytes: [0x0807f3e8, 0x0807f478), next function PUSH.
//! Raw A32 words verify two incoming plain BLs (0x080c624c, 0x080c6260),
//! zero predicated incoming BLs and zero outgoing BLs of either kind.
//! Scan from the array end for the first value <= the key. Equal values
//! do nothing; otherwise rotate smaller values toward the end, decrement
//! the allocation cursor by four, and prepend the displaced value. Cursor
//! <= limit sets error 0x62 and returns 1, preserving prior shifts without
//! increasing count. No target behavioral deviations. Native repr(C) array
//! pointers widen on hosts; allocation cursor/limit remain firmware u32s.

#[repr(C)]
pub struct BackwardSignedSet {
    pub prefix: [u32; 9],
    pub end: *mut i32,
    pub allocation_cursor: u32,
    pub allocation_limit: u32,
    pub error: u32,
    pub count: i32,
}

/// # Safety
/// `set` is writable and aligned. Count is nonnegative; the count words
/// preceding end are readable/writable and sorted ascending. On successful
/// growth, one additional preceding word must be writable. Storage must not
/// overlap the context. Cursor and limit use unsigned firmware addresses.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_set_insert_backward(
    set: *mut BackwardSignedSet,
    mut value: i32,
) -> u32 {
    unsafe {
        let count = (*set).count;
        let base = (*set).end.sub(count as usize);
        let mut index = count - 1;
        while index >= 0 {
            let existing = *base.add(index as usize);
            if existing <= value {
                if existing == value {
                    return 0;
                }
                break;
            }
            index -= 1;
        }
        while index >= 0 {
            let slot = base.add(index as usize);
            let displaced = *slot;
            *slot = value;
            value = displaced;
            index -= 1;
        }
        let cursor = (*set).allocation_cursor.wrapping_sub(4);
        (*set).allocation_cursor = cursor;
        if cursor <= (*set).allocation_limit {
            (*set).error = 0x62;
            return 1;
        }
        let new_count = count + 1;
        (*set).count = new_count;
        *(*set).end.sub(new_count as usize) = value;
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn context(end: *mut i32, count: i32, cursor: u32, limit: u32) -> BackwardSignedSet {
        BackwardSignedSet {
            prefix: [0xabcdef01; 9], end, allocation_cursor: cursor,
            allocation_limit: limit, error: 7, count,
        }
    }

    #[test]
    fn all_positions_duplicates_and_signed_extremes_match_sorted_set() {
        let mut storage = [99; 32];
        let mut set = context(unsafe { storage.as_mut_ptr().add(32) }, 0, 0x1000, 0);
        let mut expected = std::collections::BTreeSet::new();
        for key in [3, 1, 5, 4, 0, i32::MIN, i32::MAX, -1, 3, i32::MIN, i32::MAX] {
            let old_cursor = set.allocation_cursor;
            let inserted = expected.insert(key);
            assert_eq!(unsafe { signed_set_insert_backward(&mut set, key) }, 0);
            assert_eq!(set.count as usize, expected.len());
            assert_eq!(set.allocation_cursor, old_cursor - if inserted { 4 } else { 0 });
            let ordered: std::vec::Vec<_> = expected.iter().copied().collect();
            assert_eq!(&storage[32 - ordered.len()..], ordered.as_slice());
            assert!(storage[..32 - ordered.len()].iter().all(|&x| x == 99));
            assert_eq!(set.error, 7);
            assert_eq!(set.prefix, [0xabcdef01; 9]);
        }
    }

    #[test]
    fn exhaustion_preserves_shifts_count_and_unwritten_growth_slot() {
        for (cursor, limit) in [(100, 96), (100, 97)] {
            let mut storage = [77, 1, 3, 5];
            let mut set = context(unsafe { storage.as_mut_ptr().add(4) }, 3, cursor, limit);
            assert_eq!(unsafe { signed_set_insert_backward(&mut set, 4) }, 1);
            assert_eq!(storage, [77, 3, 4, 5]);
            assert_eq!(set.count, 3);
            assert_eq!(set.allocation_cursor, 96);
            assert_eq!(set.error, 0x62);
        }
    }

    #[test]
    fn empty_failure_duplicate_at_capacity_and_unsigned_cursor_wrap() {
        let mut storage = [77, 3];
        let end = unsafe { storage.as_mut_ptr().add(2) };
        let mut empty = context(end, 0, 4, 0);
        assert_eq!(unsafe { signed_set_insert_backward(&mut empty, 8) }, 1);
        assert_eq!(storage, [77, 3]);
        assert_eq!(empty.count, 0);
        assert_eq!(empty.allocation_cursor, 0);
        let mut duplicate = context(end, 1, 4, 4);
        assert_eq!(unsafe { signed_set_insert_backward(&mut duplicate, 3) }, 0);
        assert_eq!(duplicate.allocation_cursor, 4);
        assert_eq!(duplicate.error, 7);
        let mut wrapped = context(end, 1, 0, 0x80000000);
        assert_eq!(unsafe { signed_set_insert_backward(&mut wrapped, -2) }, 0);
        assert_eq!(wrapped.allocation_cursor, 0xfffffffc);
        assert_eq!(wrapped.count, 2);
        assert_eq!(storage, [-2, 3]);
    }
}
