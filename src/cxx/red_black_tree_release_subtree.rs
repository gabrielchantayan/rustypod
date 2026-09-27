//! Releases a red-black-tree subtree into its cleanup chain — original:
//! `FUN_083cd468` at load address `0x083cd468`.
//!
//! Raw `osos.dec` establishes the exact 64-byte extent: sixteen A32 words
//! from `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}`; the next separately
//! linked function begins at `0x083cd4a8`. The body has two unconditional
//! plain direct `bl` calls, at `0x083cd480` (self) and `0x083cd494` to
//! [`red_black_tree_node_prepend_and_destroy_payload`], and no predicated
//! direct calls. Whole-image decoding finds two unconditional inbound `bl`
//! sites at `0x083cd268` and the recursive `0x083cd480`, with no predicated
//! inbound calls.
//!
//! It postorder-traverses the right-link subtree at node+0x0c, snapshots the
//! successor at node+0x08 before releasing the current node, and prepends
//! each node to `chain+0x04` while destroying its payload. Deliberate
//! deviation: the recursive ARM call is expressed as Rust recursion; target
//! links remain 32-bit words so host fixtures preserve retail offsets.

const NEXT: usize = 2;
const RIGHT: usize = 3;

type ReleaseNode = unsafe extern "C" fn(*mut u32, *mut u32, u32);

/// Releases every node in the successor chain and its right subtrees.
///
/// Original: `FUN_083cd468` at load address `0x083cd468` (64 bytes; two
/// inbound plain `bl` calls and no predicated inbound calls).
///
/// # Safety
///
/// `chain` must have a writable head word at +0x04. Every reachable node must
/// have valid target-width successor and right-subtree words at +0x08/+0x0c,
/// plus the storage required by the payload destructor. RetailOS performs no
/// NULL checks beyond the node-chain terminator.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_release_subtree")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_release_subtree(chain: *mut u32, mut node: *mut u32) {
    unsafe {
        while !node.is_null() {
            red_black_tree_release_subtree(chain, node.add(RIGHT).read() as usize as *mut u32);
            let next = node.add(NEXT).read() as usize as *mut u32;
            crate::cxx::red_black_tree_node_prepend_and_destroy_payload::red_black_tree_node_prepend_and_destroy_payload(chain, node, 1);
            node = next;
        }
    }
}

unsafe fn red_black_tree_release_subtree_with(chain: *mut u32, mut node: *mut u32, release: ReleaseNode) {
    unsafe {
        while !node.is_null() {
            red_black_tree_release_subtree_with(chain, node.add(RIGHT).read() as usize as *mut u32, release);
            let next = node.add(NEXT).read() as usize as *mut u32;
            release(chain, node, 1);
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

    unsafe extern "C" fn record_release(chain: *mut u32, node: *mut u32, destroy_payload: u32) {
        assert_eq!(destroy_payload, 1);
        let index = RELEASED.fetch_add(1, Ordering::Relaxed);
        ORDER[index].store(node as usize, Ordering::Relaxed);
        unsafe {
            node.add(RIGHT).write(chain.add(1).read());
            chain.add(1).write(node as usize as u32);
        }
    }

    #[test]
    fn releases_right_subtrees_before_each_successor_and_preserves_next_snapshot() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_RELEASE_SUBTREE, 0x1000) else {
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let chain = slab.cast::<u32>();
            let first = slab.add(0x100).cast::<u32>();
            let right = slab.add(0x140).cast::<u32>();
            let second = slab.add(0x180).cast::<u32>();
            chain.add(1).write(0x1122_3344);
            first.add(NEXT).write(second as usize as u32);
            first.add(RIGHT).write(right as usize as u32);
            right.add(NEXT).write(0);
            second.add(NEXT).write(0);
            RELEASED.store(0, Ordering::Relaxed);
            for entry in &ORDER { entry.store(0, Ordering::Relaxed); }

            red_black_tree_release_subtree_with(chain, first, record_release);

            assert_eq!(RELEASED.load(Ordering::Relaxed), 3);
            assert_eq!(ORDER[0].load(Ordering::Relaxed), right as usize);
            assert_eq!(ORDER[1].load(Ordering::Relaxed), first as usize);
            assert_eq!(ORDER[2].load(Ordering::Relaxed), second as usize);
            assert_eq!(right.add(RIGHT).read(), 0x1122_3344);
            assert_eq!(first.add(RIGHT).read(), right as usize as u32);
            assert_eq!(second.add(RIGHT).read(), first as usize as u32);
            assert_eq!(chain.add(1).read(), second as usize as u32);
        }
    }

    #[test]
    fn leaves_chain_unchanged_for_a_null_root() {
        let mut chain = [0u32, 0x5566_7788];
        unsafe { red_black_tree_release_subtree_with(chain.as_mut_ptr(), core::ptr::null_mut(), record_release); }
        assert_eq!(chain[1], 0x5566_7788);
    }
}
