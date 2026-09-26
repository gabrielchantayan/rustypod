//! Counts equal unsigned-word keys in a red-black tree — original:
//! `FUN_083d7c74` @ `0x083d7c74` (96 bytes).
//!
//! Raw `osos.dec` establishes the exact 24-word A32 extent
//! `0x083d7c74..0x083d7cd4`: `e1a02001` begins the body and `e49df004`
//! returns; `e2811014` at `0x083d7cd4` begins the next separately linked
//! function. The body contains exactly two plain unconditional `bl` calls,
//! to `FUN_083bd47c` and `FUN_083e79a4`; none is predicated. The two inbound
//! sites independently decode as plain unconditional `bl` at `0x08134860` and
//! `0x08134900`, with no predicated inbound calls.
//!
//! It obtains the lower and upper bounds of `key` from the unsigned-word
//! tree, then counts the nodes in that half-open iterator range. Deliberate
//! deviation: both unported helpers remain verified-address seams; target
//! builds call the retail addresses directly and host tests install fixtures
//! that prove the wrapper's target-word ABI.

type RetailU32TreeEqualRange = unsafe extern "C" fn(*mut u32, *const u8, *const u32);
type RetailTreeIteratorDistance = unsafe extern "C" fn(*const u32, *const u32, *mut u32);

#[cfg(target_os = "none")]
const RETAIL_U32_TREE_EQUAL_RANGE_ADDRESS: usize = 0x083b_d47c;
#[cfg(target_os = "none")]
const RETAIL_TREE_ITERATOR_DISTANCE_ADDRESS: usize = 0x083e_79a4;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_u32_tree_equal_range(_: *mut u32, _: *const u8, _: *const u32) {
    panic!("u32_key_tree_count requires a retail equal-range fixture")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_tree_iterator_distance(_: *const u32, _: *const u32, _: *mut u32) {
    panic!("u32_key_tree_count requires a retail iterator-distance fixture")
}

#[cfg(not(target_os = "none"))]
static mut RETAIL_U32_TREE_EQUAL_RANGE: RetailU32TreeEqualRange = unavailable_u32_tree_equal_range;
#[cfg(not(target_os = "none"))]
static mut RETAIL_TREE_ITERATOR_DISTANCE: RetailTreeIteratorDistance = unavailable_tree_iterator_distance;

/// Counts nodes whose unsigned-word key equals `*key`.
///
/// # Safety
///
/// `tree` and `key` must meet the target-layout and lifetime requirements of
/// the retail tree helpers. `key` must reference one readable target-width word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u32_key_tree_count(tree: *const u8, key: *const u32) -> u32 {
    let mut bounds = [0u32; 2];
    #[cfg(target_os = "none")]
    let equal_range: RetailU32TreeEqualRange = unsafe { core::mem::transmute(RETAIL_U32_TREE_EQUAL_RANGE_ADDRESS) };
    #[cfg(not(target_os = "none"))]
    let equal_range = unsafe { RETAIL_U32_TREE_EQUAL_RANGE };
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

    static mut SEEN_TREE: *const u8 = core::ptr::null();
    static mut SEEN_KEY: u32 = 0;
    static mut SEEN_BOUNDS: (u32, u32) = (0, 0);

    unsafe extern "C" fn equal_range_fixture(bounds: *mut u32, tree: *const u8, key: *const u32) {
        unsafe {
            SEEN_TREE = tree;
            SEEN_KEY = key.read();
            bounds.write(0x1020_3040);
            bounds.add(1).write(0x5060_7080);
        }
    }

    unsafe extern "C" fn distance_fixture(first: *const u32, last: *const u32, count: *mut u32) {
        unsafe {
            SEEN_BOUNDS = (first.read(), last.read());
            count.write(3);
        }
    }

    #[test]
    fn passes_equal_range_bounds_to_distance_and_returns_its_count() {
        let tree = 0x1234_5000usize as *const u8;
        let key = 0xffff_fffe;
        unsafe {
            let saved_equal_range = RETAIL_U32_TREE_EQUAL_RANGE;
            let saved_distance = RETAIL_TREE_ITERATOR_DISTANCE;
            RETAIL_U32_TREE_EQUAL_RANGE = equal_range_fixture;
            RETAIL_TREE_ITERATOR_DISTANCE = distance_fixture;
            assert_eq!(u32_key_tree_count(tree, &key), 3);
            assert_eq!(SEEN_TREE, tree);
            assert_eq!(SEEN_KEY, key);
            assert_eq!(SEEN_BOUNDS, (0x1020_3040, 0x5060_7080));
            RETAIL_U32_TREE_EQUAL_RANGE = saved_equal_range;
            RETAIL_TREE_ITERATOR_DISTANCE = saved_distance;
        }
    }
}
