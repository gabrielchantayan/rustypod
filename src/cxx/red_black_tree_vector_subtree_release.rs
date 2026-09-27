//! Releases vector-valued red-black-tree nodes into their pool — original:
//! `FUN_083ba7a0` at load address `0x083ba7a0`.
//!
//! Raw `osos.dec` establishes the exact 64-byte extent: sixteen A32 words
//! from `push {r4,r5,r6,lr}` at `0x083ba7a0` through `pop {r4,r5,r6,pc}` at
//! `0x083ba7dc`; the next real function begins at `0x083ba7e0`. The body has
//! two unconditional direct `bl` instructions: its recursive call at
//! `0x083ba7b8` and [`red_black_tree_node_pool_release_vector`] at
//! `0x083ba7cc`; it has no predicated direct calls. Independent full-image
//! A32 decoding finds two inbound plain `bl` call sites and no predicated
//! inbound sites.
//!
//! It postorder-traverses each node's right subtree at +0x0c, snapshots the
//! successor at +0x08, then releases the current vector-valued node into the
//! supplied pool. Every release requests vector destruction. Deliberate
//! deviations: Rust recursion represents the direct self-call; target links
//! remain 32-bit words so host fixtures preserve retailOS offsets.

use super::red_black_tree_node_pool_acquire::RedBlackTreeNodePool;
use super::red_black_tree_node_pool_release_vector::{red_black_tree_node_pool_release_vector, RedBlackTreeVectorNode};

const NEXT: usize = 2;
const RIGHT: usize = 3;

type ReleaseNode = unsafe extern "C" fn(*mut RedBlackTreeNodePool, *mut RedBlackTreeVectorNode, u32);

/// Releases every node in a successor chain and its right subtrees.
///
/// Original: `FUN_083ba7a0` at load address `0x083ba7a0` (64 bytes; two
/// inbound plain `bl` calls and no predicated inbound calls).
///
/// # Safety
///
/// `pool` must be a writable target-layout node pool. Every reachable node
/// must have valid target-width successor and right-subtree words at
/// +0x08/+0x0c, plus a valid vector descriptor at +0x14. RetailOS only checks
/// the node-chain terminator for NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_vector_subtree_release")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_vector_subtree_release(
    pool: *mut RedBlackTreeNodePool,
    mut node: *mut RedBlackTreeVectorNode,
) {
    unsafe {
        while !node.is_null() {
            red_black_tree_vector_subtree_release(pool, (node.cast::<u32>().add(RIGHT).read() as usize) as *mut RedBlackTreeVectorNode);
            let next = (node.cast::<u32>().add(NEXT).read() as usize) as *mut RedBlackTreeVectorNode;
            red_black_tree_node_pool_release_vector(pool, node, 1);
            node = next;
        }
    }
}

unsafe fn red_black_tree_vector_subtree_release_with(
    pool: *mut RedBlackTreeNodePool,
    mut node: *mut RedBlackTreeVectorNode,
    release: ReleaseNode,
) {
    unsafe {
        while !node.is_null() {
            red_black_tree_vector_subtree_release_with(pool, (node.cast::<u32>().add(RIGHT).read() as usize) as *mut RedBlackTreeVectorNode, release);
            let next = (node.cast::<u32>().add(NEXT).read() as usize) as *mut RedBlackTreeVectorNode;
            release(pool, node, 1);
            node = next;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASED: AtomicUsize = AtomicUsize::new(0);
    static ORDER: [AtomicUsize; 4] = [
        AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    ];

    unsafe extern "C" fn record_release(
        pool: *mut RedBlackTreeNodePool,
        node: *mut RedBlackTreeVectorNode,
        destroy_vector: u32,
    ) {
        assert_eq!(destroy_vector, 1);
        let index = RELEASED.fetch_add(1, Ordering::Relaxed);
        ORDER[index].store(node as usize, Ordering::Relaxed);
        unsafe {
            node.cast::<u32>().add(RIGHT).write((*pool).free);
            (*pool).free = node as usize as u32;
        }
    }

    #[test]
    fn releases_right_subtrees_before_each_successor_and_preserves_next_snapshot() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_VECTOR_SUBTREE_RELEASE, 0x1000) else {
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let pool = slab.cast::<RedBlackTreeNodePool>();
            let first = slab.add(0x100).cast::<RedBlackTreeVectorNode>();
            let right = slab.add(0x140).cast::<RedBlackTreeVectorNode>();
            let second = slab.add(0x180).cast::<RedBlackTreeVectorNode>();
            (*pool).free = 0x1122_3344;
            first.cast::<u32>().add(NEXT).write(second as usize as u32);
            first.cast::<u32>().add(RIGHT).write(right as usize as u32);
            right.cast::<u32>().add(NEXT).write(0);
            second.cast::<u32>().add(NEXT).write(0);
            RELEASED.store(0, Ordering::Relaxed);
            for entry in &ORDER { entry.store(0, Ordering::Relaxed); }

            red_black_tree_vector_subtree_release_with(pool, first, record_release);

            assert_eq!(RELEASED.load(Ordering::Relaxed), 3);
            assert_eq!(ORDER[0].load(Ordering::Relaxed), right as usize);
            assert_eq!(ORDER[1].load(Ordering::Relaxed), first as usize);
            assert_eq!(ORDER[2].load(Ordering::Relaxed), second as usize);
            assert_eq!(right.cast::<u32>().add(RIGHT).read(), 0x1122_3344);
            assert_eq!(first.cast::<u32>().add(RIGHT).read(), right as usize as u32);
            assert_eq!(second.cast::<u32>().add(RIGHT).read(), first as usize as u32);
            assert_eq!((*pool).free, second as usize as u32);
        }
    }

    #[test]
    fn leaves_pool_unchanged_for_a_null_root() {
        let mut pool = RedBlackTreeNodePool { free: 0x5566_7788, ..Default::default() };
        unsafe { red_black_tree_vector_subtree_release_with(&mut pool, core::ptr::null_mut(), record_release); }
        assert_eq!(pool.free, 0x5566_7788);
    }
}
