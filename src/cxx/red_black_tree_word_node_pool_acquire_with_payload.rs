//! Red-black-tree word-node pool acquire with payload — original: `FUN_083bf4dc`
//! at load address `0x083bf4dc`.
//!
//! Raw `osos.dec` establishes the exact 28-byte extent: seven ARM words from
//! `push {r4,lr}` at `0x083bf4dc` through `pop {r4,pc}` at `0x083bf4f4`; the
//! next real function starts at `0x083bf4f8`. The body has one unconditional
//! `bl`, to `red_black_tree_word_node_pool_acquire` at `0x083bf424`, and no
//! predicated `bl` instructions. Two direct inbound call sites use plain `bl`.
//!
//! Acquires a word-payload red-black-tree node, then copies the caller's payload
//! word into node+0x10 when acquisition returns non-null.
//!
//! Deliberate deviations: none.

use super::red_black_tree_word_node_pool_acquire::{
    red_black_tree_word_node_pool_acquire, RedBlackTreeWordNode, RedBlackTreeWordNodePool,
};

/// Acquires a node from `pool` and initializes its word payload from `payload`.
///
/// # Safety
/// `pool` must identify valid pool state and `payload` must identify a readable
/// word. The checked allocator must return writable storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_word_node_pool_acquire_with_payload(
    pool: *mut RedBlackTreeWordNodePool,
    payload: *const u32,
) -> *mut RedBlackTreeWordNode {
    let node = red_black_tree_word_node_pool_acquire(pool);
    if !node.is_null() {
        (*node).payload = *payload;
    }
    node
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn acquires_free_node_and_replaces_its_payload_word() {
        let Some(slab) = try_map_u32_slab(
            hints::RED_BLACK_TREE_WORD_NODE_POOL_ACQUIRE_WITH_PAYLOAD,
            0x1000,
        ) else {
            assert!(note_missing_u32_fixture("cxx/red_black_tree_word_node_pool_acquire_with_payload"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let node = slab.cast::<RedBlackTreeWordNode>();
            (*node).color = 1;
            (*node).parent = 0x1111_1111;
            (*node).left = 0x2222_2222;
            (*node).right = 0;
            (*node).payload = 0xaaaa_aaaa;
            let mut pool = RedBlackTreeWordNodePool {
                chunks: 0,
                free: node as usize as u32,
                next: 0,
                end: 0,
            };
            let payload = 0x1234_5678;

            assert_eq!(
                red_black_tree_word_node_pool_acquire_with_payload(&mut pool, &payload),
                node,
            );
            assert_eq!(pool.free, 0);
            assert_eq!((*node).color, 0);
            assert_eq!((*node).parent, 0);
            assert_eq!((*node).left, 0);
            assert_eq!((*node).right, 0);
            assert_eq!((*node).payload, payload);
        }
    }
}
