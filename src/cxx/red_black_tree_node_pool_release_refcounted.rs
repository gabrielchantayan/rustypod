//! Releases a refcounted red-black-tree node into its pool — original:
//! `FUN_083c64b4` at load address `0x083c64b4`.
//!
//! Raw `osos.dec` establishes the true 36-byte extent: nine ARM words from
//! `push {r4-r6,lr}` at `0x083c64b4` through `pop {r4-r6,pc}` at
//! `0x083c64d8`; the independently entered erase helper begins at
//! `0x083c64dc`. Decoding aligned ARM branch words finds three inbound direct
//! calls (two plain `bl`, one `blne`) and one outbound predicated `blne` at
//! `0x083c64d0`, to the ported [`refcounted_body_release_dtor`] at
//! `0x0839cbc0`.
//!
//! The node's right-link becomes the pool free-list link, then the node is
//! made the new free-list head. When requested, its payload handle at +0x14
//! is released before that insertion. Deliberate deviation: host `usize`
//! pointers are bounced through the target-width payload word; target objects
//! retain the exact 24-byte node layout.

use super::red_black_tree_node_pool_acquire::RedBlackTreeNodePool;
use crate::cxx::handle::{refcounted_body_release_dtor, RefcountedBody};

/// A 24-byte red-black-tree node whose second payload word is a refcounted
/// body handle.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreeRefcountedNode {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub key: u32,
    pub refcounted_body: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(RedBlackTreeRefcountedNode, refcounted_body)];
const _: [u8; 0x18] = [0; core::mem::size_of::<RedBlackTreeRefcountedNode>()];

/// Releases `node`'s optional refcounted payload, then prepends it to `pool`'s
/// free list.
///
/// Original: `FUN_083c64b4` at `0x083c64b4` (36 bytes; two unconditional and
/// one predicated inbound `bl` sites; one outbound `blne`).
///
/// # Safety
/// `pool` and `node` must be valid writable target-layout records. When
/// `release_payload` is nonzero, `node.refcounted_body` must be zero or encode
/// a valid [`RefcountedBody`] pointer suitable for [`refcounted_body_release_dtor`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_node_pool_release_refcounted(
    pool: *mut RedBlackTreeNodePool,
    node: *mut RedBlackTreeRefcountedNode,
    release_payload: u32,
) {
    (*node).right = (*pool).free;
    if release_payload != 0 {
        #[cfg(target_os = "none")]
        refcounted_body_release_dtor((&mut (*node).refcounted_body as *mut u32).cast::<*mut RefcountedBody>());
        #[cfg(not(target_os = "none"))]
        {
            let mut body = (*node).refcounted_body as usize as *mut RefcountedBody;
            refcounted_body_release_dtor(&mut body);
            (*node).refcounted_body = body as usize as u32;
        }
    }
    (*pool).free = node as usize as u32;
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static OPS_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn word<T>(pointer: *mut T) -> u32 {
        pointer as usize as u32
    }

    #[test]
    fn prepends_and_optionally_releases_payload() {
        let _lock = OPS_LOCK.lock();
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_NODE_POOL_RELEASE_REFCOUNTED,
            0x1000,
        )
        .unwrap() as *mut u8;
        unsafe {
            let pool = slab.add(0x100).cast::<RedBlackTreeNodePool>();
            let old_free = slab.add(0x200).cast::<RedBlackTreeRefcountedNode>();
            let untouched = slab.add(0x300).cast::<RedBlackTreeRefcountedNode>();
            let released = slab.add(0x400).cast::<RedBlackTreeRefcountedNode>();
            let body = slab.add(0x500).cast::<RefcountedBody>();
            ptr::write(pool, RedBlackTreeNodePool { free: word(old_free), ..Default::default() });
            ptr::write_bytes(untouched, 0, 1);
            (*untouched).right = 0xdead_beef;
            (*untouched).refcounted_body = 0x1234_5678;

            red_black_tree_node_pool_release_refcounted(pool, untouched, 0);

            assert_eq!((*untouched).right, word(old_free));
            assert_eq!((*untouched).refcounted_body, 0x1234_5678);
            assert_eq!((*pool).free, word(untouched));

            ptr::write_bytes(released, 0, 1);
            (*released).refcounted_body = word(body);
            ptr::write(body, RefcountedBody { opaque0: 0, refcount: 2, mutex: ptr::null_mut() });

            red_black_tree_node_pool_release_refcounted(pool, released, 1);

            assert_eq!((*body).refcount, 1);
            assert_eq!((*released).refcounted_body, 0);
            assert_eq!((*released).right, word(untouched));
            assert_eq!((*pool).free, word(released));
        }
    }
}
