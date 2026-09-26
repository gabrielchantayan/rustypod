//! `tree_children_flatten_into_parent` — original: `FUN_083bfe30` @
//! `0x083bfe30`.
//!
//! Raw `osos.dec` establishes the exact 60-byte A32 extent
//! `0x083bfe30..0x083bfe6b`: the next independently entered function begins
//! with `stmdb sp!, {r2,r3,r4,r5,r6,r7,r8,r9,sl,lr}` at `0x083bfe6c`.
//! There are two verified inbound plain `bl` call sites (`0x083bfab0` and the
//! recursive call at `0x083bfe48`) and zero predicated `bl` forms. The body
//! has one plain recursive `bl` and no predicated calls. It depth-first
//! flattens a sibling chain: each node's child chain at `+0x0c` is flattened
//! first, then the node is prepended to the parent container's `+0x04` head;
//! sibling traversal uses `+0x08`.
//!
//! # Deliberate deviations
//!
//! Target pointers remain `u32` words rather than Rust pointers, preserving
//! the retail four-byte field layout on 64-bit host test builds.

/// Flattens `first_child` and its descendants into `parent`'s child-head link.
///
/// `parent` and all nonzero target-word node addresses must be valid aligned
/// writable pointers. As in retailOS, `parent` is not NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tree_children_flatten_into_parent")]
pub unsafe extern "C" fn tree_children_flatten_into_parent(parent: *mut u32, mut first_child: u32) {
    while first_child != 0 {
        let node = first_child as usize as *mut u32;
        unsafe { tree_children_flatten_into_parent(parent, core::ptr::read_volatile(node.add(3))) };
        let parent_head = unsafe { core::ptr::read_volatile(parent.add(1)) };
        first_child = unsafe { core::ptr::read_volatile(node.add(2)) };
        unsafe { core::ptr::write_volatile(node.add(3), parent_head) };
        unsafe { core::ptr::write_volatile(parent.add(1), node as usize as u32) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::tree_children_flatten_into_parent;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const WORDS: usize = 0x1000;
    const PARENT: usize = 0;
    const EXISTING: usize = 8;
    const FIRST: usize = 16;
    const SECOND: usize = 24;
    const GRANDCHILD: usize = 32;
    const GRANDCHILD_SIBLING: usize = 40;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TREE_CHILDREN_FLATTEN_INTO_PARENT, WORDS * core::mem::size_of::<u32>())
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    fn slab() -> Option<*mut u32> {
        (*SLAB).map(|address| address as *mut u32)
    }

    #[test]
    fn leaves_existing_head_unchanged_for_empty_child_chain() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(PARENT + 1).write(base.add(EXISTING) as usize as u32);
            tree_children_flatten_into_parent(base.add(PARENT), 0);
            assert_eq!(base.add(PARENT + 1).read(), base.add(EXISTING) as usize as u32);
        }
    }

    #[test]
    fn recursively_prepends_nodes_in_depth_first_order() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(PARENT + 1).write(base.add(EXISTING) as usize as u32);
            base.add(FIRST + 2).write(base.add(SECOND) as usize as u32);
            base.add(FIRST + 3).write(base.add(GRANDCHILD) as usize as u32);
            base.add(SECOND + 2).write(0);
            base.add(SECOND + 3).write(0);
            base.add(GRANDCHILD + 2).write(base.add(GRANDCHILD_SIBLING) as usize as u32);
            base.add(GRANDCHILD + 3).write(0);
            base.add(GRANDCHILD_SIBLING + 2).write(0);
            base.add(GRANDCHILD_SIBLING + 3).write(0);

            tree_children_flatten_into_parent(base.add(PARENT), base.add(FIRST) as usize as u32);

            assert_eq!(base.add(PARENT + 1).read(), base.add(SECOND) as usize as u32);
            assert_eq!(base.add(SECOND + 3).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(FIRST + 3).read(), base.add(GRANDCHILD_SIBLING) as usize as u32);
            assert_eq!(base.add(GRANDCHILD_SIBLING + 3).read(), base.add(GRANDCHILD) as usize as u32);
            assert_eq!(base.add(GRANDCHILD + 3).read(), base.add(EXISTING) as usize as u32);
        }
    }
}
