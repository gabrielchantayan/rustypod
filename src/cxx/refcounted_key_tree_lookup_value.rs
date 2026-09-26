//! `refcounted_key_tree_lookup_value` — original: `FUN_083db7e8` @ `0x083db7e8`
//! (100 bytes).
//!
//! Raw `osos.dec` establishes the exact 25-word extent from `push {r4,r5,lr}`
//! through `pop {r4,r5,pc}`; `0x083db84c` begins the next separately linked
//! function. The two Ghidra-reported inbound sites independently decode as
//! unconditional plain `bl` at 0x081b5880 and 0x081b5cf4; neither is
//! predicated. The body has four unconditional calls: acquire the null
//! temporary, retail lookup/insert at 0x083c6acc, then two releases.
//!
//! Looks up or inserts the refcounted-body key in the tree and returns the
//! selected node's payload word at +0x14. The two empty handle temporaries are
//! retained because they are explicit calls in the retail body. Deliberate
//! deviation: the unported lookup/insert remains a target-address seam; host
//! tests install a fixture while target builds invoke 0x083c6acc directly.

use crate::cxx::handle::{refcounted_body_acquire_dtor, refcounted_body_release_dtor, RefcountedBody};

type RetailRefcountedKeyTreeLookup = unsafe extern "C" fn(*mut u32, *mut u8, *const *mut RefcountedBody);

#[cfg(target_os = "none")]
const RETAIL_REFCOUNTED_KEY_TREE_LOOKUP_ADDRESS: usize = 0x083c_6acc;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_refcounted_key_tree_lookup(
    _: *mut u32,
    _: *mut u8,
    _: *const *mut RefcountedBody,
) {
    panic!("refcounted_key_tree_lookup_value requires a retail lookup fixture")
}

#[cfg(not(target_os = "none"))]
static mut RETAIL_REFCOUNTED_KEY_TREE_LOOKUP: RetailRefcountedKeyTreeLookup = unavailable_refcounted_key_tree_lookup;

/// # Safety
/// `tree` and `key_slot` must meet the retail lookup's target-layout and
/// lifetime requirements. In particular, `key_slot` must point to a valid
/// refcounted-body pointer slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_key_tree_lookup_value(
    tree: *mut u8,
    key_slot: *const *mut RefcountedBody,
) -> u32 {
    let mut first_temporary: *mut RefcountedBody = core::ptr::null_mut();
    let mut second_temporary: *mut RefcountedBody = core::ptr::null_mut();
    let mut node = 0u32;

    unsafe {
        refcounted_body_acquire_dtor(&mut second_temporary, core::ptr::null_mut());
        #[cfg(target_os = "none")]
        let lookup: RetailRefcountedKeyTreeLookup = core::mem::transmute(RETAIL_REFCOUNTED_KEY_TREE_LOOKUP_ADDRESS);
        #[cfg(not(target_os = "none"))]
        let lookup = RETAIL_REFCOUNTED_KEY_TREE_LOOKUP;
        lookup(&mut node, tree, key_slot);
        refcounted_body_release_dtor(&mut second_temporary);
        refcounted_body_release_dtor(&mut first_temporary);
    }

    node.wrapping_add(0x14)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED_TREE: *mut u8 = core::ptr::null_mut();
    static mut OBSERVED_KEY: *mut RefcountedBody = core::ptr::null_mut();
    static mut LOOKUP_NODE: u32 = 0;

    unsafe extern "C" fn lookup_fixture(result: *mut u32, tree: *mut u8, key_slot: *const *mut RefcountedBody) {
        unsafe {
            OBSERVED_TREE = tree;
            OBSERVED_KEY = key_slot.read();
            result.write(LOOKUP_NODE);
        }
    }

    #[test]
    fn forwards_the_key_slot_and_returns_the_node_payload_offset() {
        let _guard = TEST_LOCK.lock();
        let tree = 0x1000usize as *mut u8;
        let key = 0x2000usize as *mut RefcountedBody;
        unsafe {
            let saved_lookup = RETAIL_REFCOUNTED_KEY_TREE_LOOKUP;
            RETAIL_REFCOUNTED_KEY_TREE_LOOKUP = lookup_fixture;
            LOOKUP_NODE = 0x1234_5600;
            assert_eq!(refcounted_key_tree_lookup_value(tree, &key), 0x1234_5614);
            RETAIL_REFCOUNTED_KEY_TREE_LOOKUP = saved_lookup;
            assert_eq!(OBSERVED_TREE, tree);
            assert_eq!(OBSERVED_KEY, key);
        }
    }

    #[test]
    fn wraps_the_target_word_payload_offset() {
        let _guard = TEST_LOCK.lock();
        let key = core::ptr::null_mut();
        unsafe {
            let saved_lookup = RETAIL_REFCOUNTED_KEY_TREE_LOOKUP;
            RETAIL_REFCOUNTED_KEY_TREE_LOOKUP = lookup_fixture;
            LOOKUP_NODE = 0xffff_fff0;
            assert_eq!(refcounted_key_tree_lookup_value(core::ptr::null_mut(), &key), 4);
            RETAIL_REFCOUNTED_KEY_TREE_LOOKUP = saved_lookup;
        }
    }
}
