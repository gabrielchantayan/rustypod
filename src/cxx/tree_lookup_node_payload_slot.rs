//! `tree_lookup_node_payload_slot` — original: `FUN_083db29c` @ `0x083db29c`
//! (56 bytes; true extent `0x083db29c..0x083db2d4`).
//!
//! Raw `osos.dec` words establish the 14-word A32 body from `push {lr}` through
//! `pop {pc}`; `push {r4,r5,r6,lr}` at `0x083db2d4` starts the next function.
//! The body has one plain unconditional `bl`, at `0x083db2bc` to the verified,
//! still-unported `FUN_083bd024` retail address, and no predicated `bl`. Raw
//! whole-image decoding finds two inbound plain unconditional `bl` calls at
//! `0x0809dd90` and `0x0809e110`, with no predicated inbound calls.
//!
//! The wrapper copies the caller's target-width key word, asks the retail tree
//! operation for a node, and returns the node's writable payload slot at +0x14.
//! Deliberate deviation: `FUN_083bd024` has no established semantic identity,
//! so it remains an address-verified seam; target builds call it directly and
//! host tests install a fixture that proves the observable ABI.

/// ABI of the verified but unported retail callee at `0x083bd024`.
type Retail083bd024 = unsafe extern "C" fn(*mut u32, *mut u8, *const u32);

#[cfg(target_os = "none")]
const RETAIL_083BD024_ADDRESS: usize = 0x083b_d024;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_retail_083bd024(_: *mut u32, _: *mut u8, _: *const u32) {
    panic!("tree_lookup_node_payload_slot requires a retail tree-operation fixture")
}

#[cfg(not(target_os = "none"))]
static mut RETAIL_083BD024: Retail083bd024 = unavailable_retail_083bd024;

/// Calls the retail tree operation and returns its selected node's +0x14 slot.
///
/// # Safety
/// `tree` and `key_slot` must satisfy the unported retail operation's
/// target-layout and lifetime requirements. `key_slot` must reference one
/// target-width key word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tree_lookup_node_payload_slot(tree: *mut u8, key_slot: *const u32) -> u32 {
    let key = unsafe { key_slot.read() };
    let mut node = 0u32;

    unsafe {
        #[cfg(target_os = "none")]
        let lookup: Retail083bd024 = core::mem::transmute(RETAIL_083BD024_ADDRESS);
        #[cfg(not(target_os = "none"))]
        let lookup = RETAIL_083BD024;
        lookup(&mut node, tree, &key);
    }

    node.wrapping_add(0x14)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED_TREE: *mut u8 = core::ptr::null_mut();
    static mut OBSERVED_KEY: u32 = 0;
    static mut LOOKUP_NODE: u32 = 0;

    unsafe extern "C" fn lookup_fixture(result: *mut u32, tree: *mut u8, key_slot: *const u32) {
        unsafe {
            OBSERVED_TREE = tree;
            OBSERVED_KEY = key_slot.read();
            result.write(LOOKUP_NODE);
        }
    }

    struct LookupRestore(Retail083bd024);

    impl Drop for LookupRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_083BD024 = self.0 };
        }
    }

    #[test]
    fn forwards_copied_key_and_returns_node_payload_slot() {
        let _guard = TEST_LOCK.lock();
        let tree = 0x1234_5000usize as *mut u8;
        let key = 0xdead_beefu32;
        let _restore = unsafe {
            let saved = RETAIL_083BD024;
            RETAIL_083BD024 = lookup_fixture;
            LOOKUP_NODE = 0x4321_0000;
            LookupRestore(saved)
        };

        assert_eq!(unsafe { tree_lookup_node_payload_slot(tree, &key) }, 0x4321_0014);
        assert_eq!(unsafe { OBSERVED_TREE }, tree);
        assert_eq!(unsafe { OBSERVED_KEY }, key);
    }

    #[test]
    fn wraps_the_target_width_payload_offset() {
        let _guard = TEST_LOCK.lock();
        let key = 0u32;
        let _restore = unsafe {
            let saved = RETAIL_083BD024;
            RETAIL_083BD024 = lookup_fixture;
            LOOKUP_NODE = 0xffff_fff0;
            LookupRestore(saved)
        };

        assert_eq!(unsafe { tree_lookup_node_payload_slot(core::ptr::null_mut(), &key) }, 4);
    }
}
