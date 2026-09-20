//! Releases a vector-valued red-black-tree node into its pool — original:
//! `FUN_083b9ffc` at load address `0x083b9ffc`.
//!
//! Raw `osos.dec` establishes the true 40-byte extent: ten ARM words from
//! `push {r4,r5,r6,lr}` at `0x083b9ffc` through `pop {r4,r5,r6,pc}` at
//! `0x083ba020`; the separately linked left-rotation function begins at
//! `0x083ba024`. Decoding every aligned ARM branch word finds three inbound
//! plain `bl` calls and no predicated `bl` calls. Its sole outbound call is
//! `blne 0x083e4b2c`, the existing [`trivial_vector4_destruct`] seam.
//!
//! The node's right-link becomes the free-list link, its vector payload at
//! +0x14 is destroyed when requested, and the node becomes the pool head.
//! Deliberate deviations: none.

use super::red_black_tree_node_pool_acquire::RedBlackTreeNodePool;
use super::trivial_vector4_destruct::trivial_vector4_destruct;

/// A 32-byte red-black-tree node with a four-byte-element vector payload.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreeVectorNode {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub key: u32,
    pub vector_begin: u32,
    pub vector_end: u32,
    pub vector_end_of_storage: u32,
}

const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreeVectorNode, right)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(RedBlackTreeVectorNode, vector_begin)];
const _: [u8; 0x20] = [0; core::mem::size_of::<RedBlackTreeVectorNode>()];

type DestroyVector = unsafe fn(*mut u32);

#[inline(always)]
unsafe fn destroy_vector(vector: *mut u32) {
    unsafe { trivial_vector4_destruct(vector.cast::<*mut u8>()) };
}

#[inline(always)]
unsafe fn red_black_tree_node_pool_release_vector_with(
    pool: *mut RedBlackTreeNodePool,
    node: *mut RedBlackTreeVectorNode,
    destroy_value: u32,
    destroy: DestroyVector,
) {
    unsafe {
        (*node).right = (*pool).free;
        if destroy_value != 0 {
            destroy(core::ptr::addr_of_mut!((*node).vector_begin));
        }
        (*pool).free = node as usize as u32;
    }
}

/// Destroys an optional vector payload, then prepends the node to the pool.
///
/// # Safety
/// `pool` and `node` must be valid writable target-layout records. When
/// `destroy_value` is nonzero, the three words at `node + 0x14` must form a
/// vector descriptor valid for [`trivial_vector4_destruct`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_node_pool_release_vector(
    pool: *mut RedBlackTreeNodePool,
    node: *mut RedBlackTreeVectorNode,
    destroy_value: u32,
) {
    unsafe { red_black_tree_node_pool_release_vector_with(pool, node, destroy_value, destroy_vector) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static DESTROYED_VECTOR: AtomicUsize = AtomicUsize::new(0);

    unsafe fn record_vector(vector: *mut u32) {
        DESTROYED_VECTOR.store(vector as usize, Ordering::Relaxed);
    }

    fn word<T>(pointer: *mut T) -> u32 {
        pointer as usize as u32
    }

    #[test]
    fn prepends_and_only_destroys_requested_vector() {
        let _lock = LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_NODE_POOL_RELEASE_VECTOR,
            0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("cxx/red_black_tree_node_pool_release_vector"));
            return;
        };
        let slab = slab as *mut u8;
        unsafe {
            let pool = slab.add(0x100).cast::<RedBlackTreeNodePool>();
            let first = slab.add(0x200).cast::<RedBlackTreeVectorNode>();
            let second = slab.add(0x300).cast::<RedBlackTreeVectorNode>();
            let old_free = slab.add(0x400).cast::<RedBlackTreeVectorNode>();
            core::ptr::write(pool, RedBlackTreeNodePool { free: word(old_free), ..Default::default() });
            core::ptr::write_bytes(first, 0, 1);
            core::ptr::write_bytes(second, 0, 1);
            (*first).vector_begin = 0x1111_1111;
            DESTROYED_VECTOR.store(0, Ordering::Relaxed);

            red_black_tree_node_pool_release_vector_with(pool, first, 0, record_vector);

            assert_eq!((*first).right, word(old_free));
            assert_eq!((*first).vector_begin, 0x1111_1111);
            assert_eq!(DESTROYED_VECTOR.load(Ordering::Relaxed), 0);
            assert_eq!((*pool).free, word(first));

            red_black_tree_node_pool_release_vector_with(pool, second, 7, record_vector);

            assert_eq!(DESTROYED_VECTOR.load(Ordering::Relaxed), core::ptr::addr_of_mut!((*second).vector_begin) as usize);
            assert_eq!((*second).right, word(first));
            assert_eq!((*pool).free, word(second));
        }
    }
}
