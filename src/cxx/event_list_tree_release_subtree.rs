//! `event_list_tree_release_subtree` — retailOS `FUN_083c1f10` @ `0x083c1f10`
//! (64 bytes).
//!
//! Raw `osos.dec` establishes the exact A32 extent `0x083c1f10..0x083c1f4f`:
//! sixteen words from `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}`; the
//! next independently linked function starts at `0x083c1f50`. The body has two
//! plain unconditional `bl` calls and no predicated `bl` calls: recursion at
//! `0x083c1f28` and `event_list_tree_record_link` at `0x083c1f3c`.
//!
//! It postorder-traverses each node's child subtree at +0x0c, snapshots the
//! next sibling at +0x08 before teardown, then recycles the node with teardown
//! flag one. Target links remain `u32` words to preserve retail four-byte field
//! layout on 64-bit host tests.
//!
//! # Deliberate deviations
//!
//! Rust expresses the recursive `bl` as recursion; no target behavior differs.

use crate::cxx::event_list_tree_record_link::event_list_tree_record_link;

const NEXT_SIBLING: usize = 2;
const FIRST_CHILD: usize = 3;

type ReleaseRecord = unsafe extern "C" fn(*mut u8, *mut u8, i32);

/// Releases every node in a sibling chain after recursively releasing its child subtrees.
///
/// # Safety
///
/// `tree` and every reachable target-word node address must be valid aligned writable
/// pointers. Each node must provide sibling and child links at +0x08/+0x0c and the
/// storage required by [`event_list_tree_record_link`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.event_list_tree_release_subtree")]
pub unsafe extern "C" fn event_list_tree_release_subtree(tree: *mut u8, mut root: u32) {
    unsafe {
        while root != 0 {
            let node = root as usize as *mut u32;
            event_list_tree_release_subtree(tree, node.add(FIRST_CHILD).read());
            let next_sibling = node.add(NEXT_SIBLING).read();
            event_list_tree_record_link(tree, node.cast(), 1);
            root = next_sibling;
        }
    }
}

unsafe fn event_list_tree_release_subtree_with(
    tree: *mut u8,
    mut root: u32,
    release_record: ReleaseRecord,
) {
    unsafe {
        while root != 0 {
            let node = root as usize as *mut u32;
            event_list_tree_release_subtree_with(tree, node.add(FIRST_CHILD).read(), release_record);
            let next_sibling = node.add(NEXT_SIBLING).read();
            release_record(tree, node.cast(), 1);
            root = next_sibling;
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

    unsafe extern "C" fn record_release(tree: *mut u8, node: *mut u8, teardown: i32) {
        assert_eq!(teardown, 1);
        let index = RELEASED.fetch_add(1, Ordering::Relaxed);
        ORDER[index].store(node as usize, Ordering::Relaxed);
        unsafe {
            node.cast::<u32>().add(FIRST_CHILD).write(tree.cast::<u32>().add(1).read());
            tree.cast::<u32>().add(1).write(node as usize as u32);
        }
    }

    #[test]
    fn releases_child_subtrees_before_siblings_and_snapshots_next() {
        let Some(slab) = try_map_u32_slab(hints::EVENT_LIST_TREE_RELEASE_SUBTREE, 0x1000) else {
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let tree = slab;
            let first = slab.add(0x100).cast::<u32>();
            let child = slab.add(0x140).cast::<u32>();
            let second = slab.add(0x180).cast::<u32>();
            tree.cast::<u32>().add(1).write(0x1122_3344);
            first.add(NEXT_SIBLING).write(second as usize as u32);
            first.add(FIRST_CHILD).write(child as usize as u32);
            child.add(NEXT_SIBLING).write(0);
            child.add(FIRST_CHILD).write(0);
            second.add(NEXT_SIBLING).write(0);
            second.add(FIRST_CHILD).write(0);
            RELEASED.store(0, Ordering::Relaxed);
            for entry in &ORDER { entry.store(0, Ordering::Relaxed); }

            event_list_tree_release_subtree_with(tree, first as usize as u32, record_release);

            assert_eq!(RELEASED.load(Ordering::Relaxed), 3);
            assert_eq!(ORDER[0].load(Ordering::Relaxed), child as usize);
            assert_eq!(ORDER[1].load(Ordering::Relaxed), first as usize);
            assert_eq!(ORDER[2].load(Ordering::Relaxed), second as usize);
            assert_eq!(child.add(FIRST_CHILD).read(), 0x1122_3344);
            assert_eq!(first.add(FIRST_CHILD).read(), child as usize as u32);
            assert_eq!(second.add(FIRST_CHILD).read(), first as usize as u32);
            assert_eq!(tree.cast::<u32>().add(1).read(), second as usize as u32);
        }
    }

    #[test]
    fn leaves_tree_unchanged_for_a_null_root() {
        let mut tree = [0u32, 0x5566_7788];
        unsafe { event_list_tree_release_subtree_with(tree.as_mut_ptr().cast(), 0, record_release); }
        assert_eq!(tree[1], 0x5566_7788);
    }
}
