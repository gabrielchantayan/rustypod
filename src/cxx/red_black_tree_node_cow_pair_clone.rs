//! Red-black-tree node COW-pair clone — retailOS `FUN_083c411c` at load
//! address `0x083c411c` (52 bytes).
//!
//! Raw `osos.dec` establishes the exact 13-word A32 extent from `push
//! {r4,r5,r6,lr}` at `0x083c411c` through `pop {r4,r5,r6,pc}` at
//! `0x083c414c`; `0x083c4150` begins the next real function. The body has
//! three unconditional plain `bl` instructions (one to
//! `red_black_tree_node_cow_pair_pool_acquire` at `0x083c4064`, then two to
//! `cxx_string_copy_ctor` at `0x083d8c30`) and no predicated `bl` instructions.
//! Whole-image raw A32 decoding finds two unconditional inbound direct `bl`
//! sites and no predicated inbound calls.
//!
//! It acquires a 24-byte tree node, then COW-copy-constructs the two string
//! words in its payload at `+0x10` and `+0x14`. It returns the acquired node.
//! Deliberate deviations: target-width string fields pass through native-width
//! locals before being stored as u32 words, preserving the target layout without
//! 64-bit overlap.

use crate::cxx::red_black_tree_node_cow_pair_pool_acquire::{
    red_black_tree_node_cow_pair_pool_acquire, RedBlackTreeNodeCowPairPool,
};
use crate::cxx::string::cxx_string_copy_ctor;

/// Acquires a tree node and copy-constructs its two-word COW-string payload.
///
/// # Safety
///
/// `pool` must satisfy the retail COW-string-pair node-pool acquire contract;
/// the acquired node must be writable through `+0x17` and `payload` must
/// identify two valid COW string words.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_node_cow_pair_clone")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_node_cow_pair_clone(
    pool: *mut RedBlackTreeNodeCowPairPool,
    payload: *const u8,
) -> *mut u8 {
    let node = unsafe { red_black_tree_node_cow_pair_pool_acquire(pool) }.cast::<u8>();
    let destination = (node as usize as u32).wrapping_add(0x10) as usize as *mut u8;
    if !destination.is_null() {
        unsafe {
            let first_source = payload.cast::<u32>().read() as usize as *mut u8;
            let second_source = payload.add(4).cast::<u32>().read() as usize as *mut u8;
            let mut first_destination = core::ptr::null_mut();
            let mut second_destination = core::ptr::null_mut();
            cxx_string_copy_ctor(&mut first_destination, &first_source);
            cxx_string_copy_ctor(&mut second_destination, &second_source);
            destination.cast::<u32>().write(first_destination as usize as u32);
            destination.add(4).cast::<u32>().write(second_destination as usize as u32);
        }
    }
    node
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn put_word(base: *mut u8, offset: usize, value: *mut u8) {
        unsafe { base.add(offset).cast::<u32>().write(value as usize as u32) }
    }

    unsafe fn word(base: *mut u8, offset: usize) -> u32 { unsafe { base.add(offset).cast::<u32>().read() } }

    #[test]
    fn acquires_node_and_cow_copies_both_payload_words() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_NODE_COW_PAIR_CLONE, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/red_black_tree_node_cow_pair_clone"));
            return;
        };
        unsafe {
            let first_data = slab.add(0x600);
            let second_data = slab.add(0x680);
            first_data.sub(12).cast::<u32>().write(3);
            second_data.sub(12).cast::<u32>().write(7);
            let payload = slab.add(0x40);
            put_word(payload, 0, first_data);
            put_word(payload, 4, second_data);
            let node = slab.add(0x100);
            let mut pool = RedBlackTreeNodeCowPairPool {
                free: node as usize as u32,
                ..RedBlackTreeNodeCowPairPool::default()
            };
            put_word(node, 0x0c, core::ptr::null_mut());
            let result = red_black_tree_node_cow_pair_clone(&mut pool, payload);
            assert_eq!(result, node);
            assert_eq!(word(node, 0x10) as usize, first_data as usize);
            assert_eq!(word(node, 0x14) as usize, second_data as usize);
            assert_eq!(first_data.sub(12).cast::<u32>().read(), 4);
            assert_eq!(second_data.sub(12).cast::<u32>().read(), 8);
        }
    }

}
