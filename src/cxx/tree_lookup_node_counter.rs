//! `tree_lookup_node_counter` — original: `FUN_083db164` @ `0x083db164`
//! (56 bytes; true extent `0x083db164..0x083db19c`).
//!
//! Raw `osos.dec` words establish the 14-word A32 body from `push {lr}` through
//! `pop {pc}`; `push {r4,r5,r6,lr}` at `0x083db19c` starts the next function.
//! The body has one plain unconditional `bl`, at `0x083db184` to the verified,
//! still-unported `FUN_083bc5e0` retail address, and no predicated `bl`. Raw
//! whole-image decoding finds two inbound plain unconditional `bl` calls at
//! `0x08124ba8` and `0x08124bc0`, with no predicated inbound calls.
//!
//! The wrapper copies the caller's target-width key word into the first word of
//! a zero-terminated key pair, asks the retail tree operation for a node, and
//! returns the node's writable counter slot at +0x14. Deliberate deviation:
//! `FUN_083bc5e0` has no established semantic identity, so it remains an
//! address-verified seam; target builds call it directly and host tests install
//! a fixture that proves the observable ABI.

#[repr(C)]
struct TreeLookupResult {
    node: u32,
    matched: u8,
}

#[repr(C)]
struct TreeKeyPair {
    key: u32,
    terminator: u32,
}

/// ABI of the verified but unported retail callee at `0x083bc5e0`.
type Retail083bc5e0 = unsafe extern "C" fn(*mut TreeLookupResult, *mut u8, *const TreeKeyPair);

#[cfg(target_os = "none")]
const RETAIL_083BC5E0_ADDRESS: usize = 0x083b_c5e0;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_retail_083bc5e0(_: *mut TreeLookupResult, _: *mut u8, _: *const TreeKeyPair) {
    panic!("tree_lookup_node_counter requires a retail tree-operation fixture")
}

#[cfg(not(target_os = "none"))]
static mut RETAIL_083BC5E0: Retail083bc5e0 = unavailable_retail_083bc5e0;

/// Calls the retail tree operation and returns its selected node's +0x14 counter slot.
///
/// # Safety
/// `tree` and `key_slot` must satisfy the unported retail operation's
/// target-layout and lifetime requirements. `key_slot` must reference one
/// target-width key word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tree_lookup_node_counter(tree: *mut u8, key_slot: *const u32) -> u32 {
    let key = unsafe { key_slot.read() };
    let key_pair = TreeKeyPair { key, terminator: 0 };
    let mut result = TreeLookupResult { node: 0, matched: 0 };

    #[cfg(target_os = "none")]
    let lookup: Retail083bc5e0 = unsafe { core::mem::transmute(RETAIL_083BC5E0_ADDRESS) };
    #[cfg(not(target_os = "none"))]
    let lookup = unsafe { RETAIL_083BC5E0 };

    unsafe { lookup(&mut result, tree, &key_pair) };
    result.node.wrapping_add(0x14)
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut SEEN_TREE: *mut u8 = core::ptr::null_mut();
    static mut SEEN_KEY_PAIR: (u32, u32) = (0, 1);
    static mut RESULT_NODE: u32 = 0;

    unsafe extern "C" fn lookup_fixture(result: *mut TreeLookupResult, tree: *mut u8, key: *const TreeKeyPair) {
        unsafe {
            SEEN_TREE = tree;
            SEEN_KEY_PAIR = ((*key).key, (*key).terminator);
            (*result).node = RESULT_NODE;
            (*result).matched = 1;
        }
    }

    #[test]
    fn copies_key_and_returns_counter_slot_with_u32_wrapping() {
        let tree = 0x1000usize as *mut u8;
        let key = 0x89ab_cdef;
        unsafe {
            let saved_lookup = RETAIL_083BC5E0;
            RETAIL_083BC5E0 = lookup_fixture;
            RESULT_NODE = u32::MAX - 0x13;
            assert_eq!(tree_lookup_node_counter(tree, &key), 0);
            assert_eq!(SEEN_TREE, tree);
            assert_eq!(SEEN_KEY_PAIR, (key, 0));
            RETAIL_083BC5E0 = saved_lookup;
        }
    }
}
