//! `u32_key_tree_equal_range_count` — retailOS `FUN_083d7178` at load address
//! `0x083d7178`.
//!
//! Raw `osos.dec` establishes the exact 96-byte extent,
//! `0x083d7178..0x083d71d4`; the next separately linked function starts at
//! `0x083d71d8`. The body contains two unconditional plain `bl` instructions
//! (`0x083d718c` to equal-range at `0x083b7ff0`, and `0x083d71c8` to range
//! count at `0x083e7a40`) and zero predicated `bl` instructions.
//!
//! It obtains the equal range for a `u32` key in a red-black tree, then counts
//! the half-open iterator range. Deliberate deviations: stack temporaries are
//! Rust locals; the two unported retail helpers are narrow target dispatches
//! and replaceable host-test seams.

pub type U32KeyTreeEqualRange = unsafe extern "C" fn(*mut u32, *mut u8, *const u32);
pub type RedBlackTreeRangeCount = unsafe extern "C" fn(*const u32, *const u32, *mut u32);

#[derive(Clone, Copy)]
pub struct U32KeyTreeEqualRangeCountOps {
    pub equal_range: U32KeyTreeEqualRange,
    pub range_count: RedBlackTreeRangeCount,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_ops() -> U32KeyTreeEqualRangeCountOps {
    U32KeyTreeEqualRangeCountOps {
        equal_range: core::mem::transmute(0x083b_7ff0usize),
        range_count: core::mem::transmute(0x083e_7a40usize),
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_equal_range(_range: *mut u32, _tree: *mut u8, _key: *const u32) {
    panic!("u32_key_tree_equal_range_count requires test operations on host")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_range_count(_first: *const u32, _last: *const u32, _count: *mut u32) {
    panic!("u32_key_tree_equal_range_count requires test operations on host")
}

#[cfg(not(target_os = "none"))]
pub static mut U32_KEY_TREE_EQUAL_RANGE_COUNT_OPS: U32KeyTreeEqualRangeCountOps = U32KeyTreeEqualRangeCountOps {
    equal_range: unavailable_equal_range,
    range_count: unavailable_range_count,
};

#[inline(always)]
unsafe fn u32_key_tree_equal_range_count_ops() -> U32KeyTreeEqualRangeCountOps {
    #[cfg(target_os = "none")]
    { retail_ops() }
    #[cfg(not(target_os = "none"))]
    { core::ptr::read_volatile(core::ptr::addr_of!(U32_KEY_TREE_EQUAL_RANGE_COUNT_OPS)) }
}

/// Counts the entries equal to `*key` in `tree`.
///
/// # Safety
///
/// `tree` must designate a live retailOS red-black tree, and `key` must be
/// readable. The equal-range and range-count helpers must accept the returned
/// target-width iterator words.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.u32_key_tree_equal_range_count")]
#[inline(never)]
pub unsafe extern "C" fn u32_key_tree_equal_range_count(tree: *mut u8, key: *const u32) -> u32 {
    let ops = u32_key_tree_equal_range_count_ops();
    let mut range = [0u32; 2];
    (ops.equal_range)(range.as_mut_ptr(), tree, key);

    let mut count = 0;
    (ops.range_count)(range.as_ptr(), range.as_ptr().add(1), &mut count);
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RANGE: [u32; 2] = [0; 2];
    static mut SEEN_TREE: *mut u8 = ptr::null_mut();
    static mut SEEN_KEY: u32 = 0;
    static mut SEEN_RANGE: [u32; 2] = [0; 2];
    static mut RANGE_COUNT_CALLS: u32 = 0;
    static mut RETURNED_COUNT: u32 = 0;

    unsafe extern "C" fn equal_range(result: *mut u32, tree: *mut u8, key: *const u32) {
        SEEN_TREE = tree;
        SEEN_KEY = key.read();
        result.copy_from_nonoverlapping(RANGE.as_ptr(), 2);
    }

    unsafe extern "C" fn range_count(first: *const u32, last: *const u32, count: *mut u32) {
        SEEN_RANGE = [first.read(), last.read()];
        RANGE_COUNT_CALLS += 1;
        count.write(RETURNED_COUNT);
    }

    struct Reset(U32KeyTreeEqualRangeCountOps);
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { U32_KEY_TREE_EQUAL_RANGE_COUNT_OPS = self.0; } }
    }

    unsafe fn install(range: [u32; 2], count: u32) -> Reset {
        let old = U32_KEY_TREE_EQUAL_RANGE_COUNT_OPS;
        U32_KEY_TREE_EQUAL_RANGE_COUNT_OPS = U32KeyTreeEqualRangeCountOps { equal_range, range_count };
        RANGE = range; SEEN_TREE = ptr::null_mut(); SEEN_KEY = 0; SEEN_RANGE = [0; 2];
        RANGE_COUNT_CALLS = 0; RETURNED_COUNT = count;
        Reset(old)
    }

    #[test]
    fn empty_equal_range_is_forwarded_to_the_count_helper() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let _reset = install([0x2000, 0x2000], 0);
            let tree = 0x1234usize as *mut u8;
            assert_eq!(u32_key_tree_equal_range_count(tree, &0xfeed_beefu32), 0);
            assert_eq!(SEEN_TREE, tree);
            assert_eq!(SEEN_KEY, 0xfeed_beef);
            assert_eq!(SEEN_RANGE, [0x2000, 0x2000]);
            assert_eq!(RANGE_COUNT_CALLS, 1);
        }
    }

    #[test]
    fn returns_the_range_helper_count_for_distinct_iterator_bounds() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let _reset = install([0x1000, 0x1800], 3);
            assert_eq!(u32_key_tree_equal_range_count(ptr::null_mut(), &7), 3);
            assert_eq!(SEEN_RANGE, [0x1000, 0x1800]);
            assert_eq!(RANGE_COUNT_CALLS, 1);
        }
    }
}
