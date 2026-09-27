//! Releases a refcounted red-black-tree subtree into its node pool — original:
//! `FUN_083c6c58` at load address `0x083c6c58`.
//!
//! Raw `osos.dec` establishes the exact 64-byte extent: sixteen A32 words from
//! `push {r4-r6,lr}` at `0x083c6c58` through `pop {r4-r6,pc}` at `0x083c6c94`;
//! the next independently entered function begins at `0x083c6c98`. The body
//! has two unconditional direct `bl` calls: recursive `bl` at `0x083c6c70`
//! and `bl` at `0x083c6c84` to
//! [`red_black_tree_node_pool_release_refcounted`]; it has no predicated `bl`
//! calls.
//!
//! It postorder-traverses each node's right subtree, snapshots the successor at
//! node+0x08 before releasing the current node, then returns the node to the
//! pool. Deliberate deviation: Rust recursion represents the recursive ARM
//! call; target links remain 32-bit words so host fixtures preserve retail
//! offsets.

use super::red_black_tree_node_pool_acquire::RedBlackTreeNodePool;
use super::red_black_tree_node_pool_release_refcounted::{
    red_black_tree_node_pool_release_refcounted, RedBlackTreeRefcountedNode,
};

/// Releases every node in the successor chain and its right subtrees.
///
/// Original: `FUN_083c6c58` at `0x083c6c58` (64 bytes; two unconditional
/// outbound plain `bl` calls, no predicated `bl` calls).
///
/// # Safety
///
/// `pool` must have a writable free-list word at +0x04. Every reachable node
/// must be a valid [`RedBlackTreeRefcountedNode`], with target-width successor
/// and right-subtree words at +0x08/+0x0c and a valid optional payload handle.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_refcounted_subtree_release")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_refcounted_subtree_release(
    pool: *mut RedBlackTreeNodePool,
    mut node: *mut RedBlackTreeRefcountedNode,
) {
    while !node.is_null() {
        red_black_tree_refcounted_subtree_release(pool, (*node).right as usize as *mut RedBlackTreeRefcountedNode);
        let next = (*node).left as usize as *mut RedBlackTreeRefcountedNode;
        red_black_tree_node_pool_release_refcounted(pool, node, 1);
        node = next;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;

    fn word<T>(pointer: *mut T) -> u32 {
        pointer as usize as u32
    }

    #[test]
    fn releases_right_subtrees_before_successors_and_preserves_next_snapshot() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_REFCOUNTED_SUBTREE_RELEASE, 0x1000) else {
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let pool = slab.add(0x40).cast::<RedBlackTreeNodePool>();
            let old_free = slab.add(0x100).cast::<RedBlackTreeRefcountedNode>();
            let first = slab.add(0x140).cast::<RedBlackTreeRefcountedNode>();
            let right = slab.add(0x180).cast::<RedBlackTreeRefcountedNode>();
            let second = slab.add(0x1c0).cast::<RedBlackTreeRefcountedNode>();
            ptr::write(pool, RedBlackTreeNodePool { free: word(old_free), ..Default::default() });
            ptr::write(first, RedBlackTreeRefcountedNode::default());
            (*first).left = word(second);
            (*first).right = word(right);
            ptr::write(right, RedBlackTreeRefcountedNode::default());
            ptr::write(second, RedBlackTreeRefcountedNode::default());

            red_black_tree_refcounted_subtree_release(pool, first);

            assert_eq!((*pool).free, word(second));
            assert_eq!((*second).right, word(first));
            assert_eq!((*first).right, word(right));
            assert_eq!((*right).right, word(old_free));
        }
    }

    #[test]
    fn leaves_pool_unchanged_for_null_root() {
        let mut pool = RedBlackTreeNodePool { free: 0x5566_7788, ..Default::default() };
        unsafe { red_black_tree_refcounted_subtree_release(&mut pool, ptr::null_mut()); }
        assert_eq!(pool.free, 0x5566_7788);
    }
}
