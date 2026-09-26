//! Counts equal keys in an ordered tree — retailOS `FUN_083d71e8` @
//! `0x083d71e8` (96 bytes).
//!
//! Raw `osos.dec` establishes the exact 24-word A32 extent
//! `0x083d71e8..0x083d7248`: `e1a02001` begins the body and `e49df004`
//! returns; `e92d43f0` at `0x083d7248` starts the next separately linked
//! function. The body contains exactly two plain unconditional `bl` calls,
//! to `FUN_083b8adc` and `FUN_083e7adc`; none is predicated. It obtains the
//! equal range for `key`, then counts the nodes in that half-open iterator
//! range. Deliberate deviation: both unported helpers remain verified-address
//! seams; target builds call the retail addresses directly and host tests
//! install fixtures that prove the wrapper's target-word ABI.

type RetailTreeEqualRange = unsafe extern "C" fn(*mut u32, *const u8, *const u8);
type RetailTreeIteratorDistance = unsafe extern "C" fn(*const u32, *const u32, *mut u32);

#[cfg(target_os = "none")]
const RETAIL_TREE_EQUAL_RANGE_ADDRESS: usize = 0x083b_8adc;
#[cfg(target_os = "none")]
const RETAIL_TREE_ITERATOR_DISTANCE_ADDRESS: usize = 0x083e_7adc;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_tree_equal_range(_: *mut u32, _: *const u8, _: *const u8) {
    panic!("ordered_tree_key_count requires a retail equal-range fixture")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_tree_iterator_distance(_: *const u32, _: *const u32, _: *mut u32) {
    panic!("ordered_tree_key_count requires a retail iterator-distance fixture")
}

#[cfg(not(target_os = "none"))]
static mut RETAIL_TREE_EQUAL_RANGE: RetailTreeEqualRange = unavailable_tree_equal_range;
#[cfg(not(target_os = "none"))]
static mut RETAIL_TREE_ITERATOR_DISTANCE: RetailTreeIteratorDistance = unavailable_tree_iterator_distance;

/// Counts nodes whose key compares equivalent to `*key`.
///
/// # Safety
///
/// `tree` and `key` must meet the target-layout and lifetime requirements of
/// the retail tree helpers. The key representation is comparator-defined.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ordered_tree_key_count(tree: *const u8, key: *const u8) -> u32 {
    let mut bounds = [0u32; 2];
    #[cfg(target_os = "none")]
    let equal_range: RetailTreeEqualRange = unsafe { core::mem::transmute(RETAIL_TREE_EQUAL_RANGE_ADDRESS) };
    #[cfg(not(target_os = "none"))]
    let equal_range = unsafe { RETAIL_TREE_EQUAL_RANGE };
    unsafe { equal_range(bounds.as_mut_ptr(), tree, key) };

    let mut count = 0u32;
    #[cfg(target_os = "none")]
    let distance: RetailTreeIteratorDistance = unsafe { core::mem::transmute(RETAIL_TREE_ITERATOR_DISTANCE_ADDRESS) };
    #[cfg(not(target_os = "none"))]
    let distance = unsafe { RETAIL_TREE_ITERATOR_DISTANCE };
    unsafe { distance(bounds.as_ptr(), bounds.as_ptr().add(1), &mut count) };
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_TREE: *const u8 = core::ptr::null();
    static mut SEEN_KEY: *const u8 = core::ptr::null();
    static mut SEEN_BOUNDS: (u32, u32) = (0, 0);
    static mut DISTANCE_RESULT: u32 = 0;

    unsafe extern "C" fn equal_range_fixture(bounds: *mut u32, tree: *const u8, key: *const u8) {
        unsafe {
            SEEN_TREE = tree;
            SEEN_KEY = key;
            bounds.write(0x1020_3040);
            bounds.add(1).write(0x5060_7080);
        }
    }

    unsafe extern "C" fn distance_fixture(first: *const u32, last: *const u32, count: *mut u32) {
        unsafe {
            SEEN_BOUNDS = (first.read(), last.read());
            count.write(DISTANCE_RESULT);
        }
    }

    #[test]
    fn passes_equal_range_bounds_to_distance_and_returns_its_count() {
        let _guard = LOCK.lock();
        let tree = 0x1234_5000usize as *const u8;
        let key = [0xfe, 0xff, 0xff, 0xff];
        unsafe {
            let saved_equal_range = RETAIL_TREE_EQUAL_RANGE;
            let saved_distance = RETAIL_TREE_ITERATOR_DISTANCE;
            RETAIL_TREE_EQUAL_RANGE = equal_range_fixture;
            RETAIL_TREE_ITERATOR_DISTANCE = distance_fixture;
            DISTANCE_RESULT = 3;
            assert_eq!(ordered_tree_key_count(tree, key.as_ptr()), 3);
            assert_eq!(SEEN_TREE, tree);
            assert_eq!(SEEN_KEY, key.as_ptr());
            assert_eq!(SEEN_BOUNDS, (0x1020_3040, 0x5060_7080));
            RETAIL_TREE_EQUAL_RANGE = saved_equal_range;
            RETAIL_TREE_ITERATOR_DISTANCE = saved_distance;
        }
    }

    #[test]
    fn returns_zero_for_an_empty_equal_range() {
        let _guard = LOCK.lock();
        let tree = 0usize as *const u8;
        let key = [0u8; 1];
        unsafe {
            let saved_equal_range = RETAIL_TREE_EQUAL_RANGE;
            let saved_distance = RETAIL_TREE_ITERATOR_DISTANCE;
            RETAIL_TREE_EQUAL_RANGE = equal_range_fixture;
            RETAIL_TREE_ITERATOR_DISTANCE = distance_fixture;
            DISTANCE_RESULT = 0;
            assert_eq!(ordered_tree_key_count(tree, key.as_ptr()), 0);
            assert_eq!(SEEN_TREE, tree);
            assert_eq!(SEEN_KEY, key.as_ptr());
            RETAIL_TREE_EQUAL_RANGE = saved_equal_range;
            RETAIL_TREE_ITERATOR_DISTANCE = saved_distance;
        }
    }
}
