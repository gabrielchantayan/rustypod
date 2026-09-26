//! `tree_lookup_pair_node_payload_slot` — original: `FUN_083daf6c` @ `0x083daf6c`
//! (64 bytes; true extent `0x083daf6c..0x083dafac`).
//!
//! Raw `osos.dec` words establish the 16-word A32 body from `push {lr}` through
//! `pop {pc}`; `push {r4,r5,r6,lr}` at `0x083dafac` starts the next function.
//! The body has one plain unconditional `bl`, at `0x083daf94` to the verified,
//! still-unported `FUN_083b7ba0` retail address, and no predicated `bl`. Raw
//! whole-image decoding finds two inbound plain unconditional `bl` calls at
//! `0x08182c98` and `0x08182cc8`, with no predicated inbound calls.
//!
//! The wrapper copies a caller-supplied two-word key into a three-word target
//! record with a zero final word, asks the retail tree operation for its node,
//! and returns that node's writable payload slot at +0x18. Deliberate
//! deviation: `FUN_083b7ba0` has no established semantic identity, so it
//! remains an address-verified seam; target builds call it directly and host
//! tests install a fixture that proves the observable ABI.

/// ABI of the verified but unported retail callee at `0x083b7ba0`.
type Retail083b7ba0 = unsafe extern "C" fn(*mut u32, *mut u8, *const u32);

#[cfg(target_os = "none")]
const RETAIL_083B7BA0_ADDRESS: usize = 0x083b_7ba0;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_retail_083b7ba0(_: *mut u32, _: *mut u8, _: *const u32) {
    panic!("tree_lookup_pair_node_payload_slot requires a retail tree-operation fixture")
}

#[cfg(not(target_os = "none"))]
static mut RETAIL_083B7BA0: Retail083b7ba0 = unavailable_retail_083b7ba0;

/// Calls the retail tree operation and returns its selected node's +0x18 slot.
///
/// # Safety
/// `tree` and `key_pair` must satisfy the unported retail operation's
/// target-layout and lifetime requirements. `key_pair` must reference two
/// target-width key words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tree_lookup_pair_node_payload_slot(
    tree: *mut u8,
    key_pair: *const u32,
) -> u32 {
    let key = unsafe { [key_pair.read(), key_pair.add(1).read(), 0] };
    let mut node = 0u32;

    unsafe {
        #[cfg(target_os = "none")]
        let lookup: Retail083b7ba0 = core::mem::transmute(RETAIL_083B7BA0_ADDRESS);
        #[cfg(not(target_os = "none"))]
        let lookup = RETAIL_083B7BA0;
        lookup(&mut node, tree, key.as_ptr());
    }

    node.wrapping_add(0x18)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED_TREE: *mut u8 = core::ptr::null_mut();
    static mut OBSERVED_KEY: [u32; 3] = [0; 3];
    static mut LOOKUP_NODE: u32 = 0;

    unsafe extern "C" fn lookup_fixture(result: *mut u32, tree: *mut u8, key: *const u32) {
        unsafe {
            OBSERVED_TREE = tree;
            OBSERVED_KEY = [key.read(), key.add(1).read(), key.add(2).read()];
            result.write(LOOKUP_NODE);
        }
    }

    struct LookupRestore(Retail083b7ba0);

    impl Drop for LookupRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_083B7BA0 = self.0 };
        }
    }

    #[test]
    fn copies_pair_zero_terminates_key_and_returns_payload_slot() {
        let _guard = TEST_LOCK.lock();
        let tree = 0x1234_5000usize as *mut u8;
        let key = [0xdead_beefu32, 0x2468_ace0];
        let _restore = unsafe {
            let saved = RETAIL_083B7BA0;
            RETAIL_083B7BA0 = lookup_fixture;
            LOOKUP_NODE = 0x4321_0000;
            LookupRestore(saved)
        };

        assert_eq!(unsafe { tree_lookup_pair_node_payload_slot(tree, key.as_ptr()) }, 0x4321_0018);
        assert_eq!(unsafe { OBSERVED_TREE }, tree);
        assert_eq!(unsafe { OBSERVED_KEY }, [0xdead_beef, 0x2468_ace0, 0]);
    }

    #[test]
    fn wraps_the_target_width_payload_offset() {
        let _guard = TEST_LOCK.lock();
        let key = [0, u32::MAX];
        let _restore = unsafe {
            let saved = RETAIL_083B7BA0;
            RETAIL_083B7BA0 = lookup_fixture;
            LOOKUP_NODE = 0xffff_fff0;
            LookupRestore(saved)
        };

        assert_eq!(unsafe { tree_lookup_pair_node_payload_slot(core::ptr::null_mut(), key.as_ptr()) }, 8);
        assert_eq!(unsafe { OBSERVED_KEY }, [0, u32::MAX, 0]);
    }
}
