//! `tree_children_release_083cb574` — retailOS `FUN_083cb574` @ `0x083cb574`.
//!
//! Raw `osos.dec` establishes the exact 60-byte A32 extent
//! `0x083cb574..0x083cb5af`: `push {r2,r3,r4,r5,r6,r7,r8,r9,sl,lr}` at
//! `0x083cb5b4` starts the next independently linked function. Whole-image A32
//! branch decoding finds two inbound plain `bl` calls (`0x083cb374` and the
//! recursive call at `0x083cb58c`) and no predicated `bl` forms. The body has
//! two plain `bl` calls: recursion and `list_node_prepend_release`. It walks a
//! sibling chain at node `+0x08`, recursively processes each child chain at
//! `+0x0c`, then releases and prepends the node through the list head at `+0x04`.
//!
//! # Deliberate deviations
//!
//! Target pointers remain `u32` words rather than Rust pointers, preserving
//! the retail four-byte field layout on 64-bit host test builds.
use crate::cxx::list_node_prepend_release::list_node_prepend_release;

/// Recursively releases child chains and prepends every node to `list`.
///
/// # Safety
/// `list` and every nonzero target-word node address must be valid aligned
/// writable pointers. Nodes must satisfy [`list_node_prepend_release`]'s
/// release-chain contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tree_children_release_083cb574")]
pub unsafe extern "C" fn tree_children_release_083cb574(list: *mut u8, mut first_child: u32) {
    while first_child != 0 {
        let node = first_child as usize as *mut u8;
        unsafe { tree_children_release_083cb574(list, core::ptr::read_volatile(node.cast::<u32>().add(3))) };
        first_child = unsafe { core::ptr::read_volatile(node.cast::<u32>().add(2)) };
        unsafe { list_node_prepend_release(list, node, 1) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::tree_children_release_083cb574;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const WORDS: usize = 0x1000;
    const LIST: usize = 0;
    const EXISTING: usize = 8;
    const FIRST: usize = 16;
    const SECOND: usize = 24;
    const GRANDCHILD: usize = 32;
    const GRANDCHILD_SIBLING: usize = 40;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TREE_CHILDREN_RELEASE_083CB574, WORDS * core::mem::size_of::<u32>())
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
            base.add(LIST + 1).write(base.add(EXISTING) as usize as u32);
            tree_children_release_083cb574(base.cast(), 0);
            assert_eq!(base.add(LIST + 1).read(), base.add(EXISTING) as usize as u32);
        }
    }

    #[test]
    fn recursively_releases_and_prepends_nodes_in_depth_first_order() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(LIST + 1).write(base.add(EXISTING) as usize as u32);
            base.add(FIRST + 2).write(base.add(SECOND) as usize as u32);
            base.add(FIRST + 3).write(base.add(GRANDCHILD) as usize as u32);
            base.add(SECOND + 2).write(0);
            base.add(SECOND + 3).write(0);
            base.add(GRANDCHILD + 2).write(base.add(GRANDCHILD_SIBLING) as usize as u32);
            base.add(GRANDCHILD + 3).write(0);
            base.add(GRANDCHILD_SIBLING + 2).write(0);
            base.add(GRANDCHILD_SIBLING + 3).write(0);

            tree_children_release_083cb574(base.cast(), base.add(FIRST) as usize as u32);

            assert_eq!(base.add(LIST + 1).read(), base.add(SECOND) as usize as u32);
            assert_eq!(base.add(SECOND + 3).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(FIRST + 3).read(), base.add(GRANDCHILD_SIBLING) as usize as u32);
            assert_eq!(base.add(GRANDCHILD_SIBLING + 3).read(), base.add(GRANDCHILD) as usize as u32);
            assert_eq!(base.add(GRANDCHILD + 3).read(), base.add(EXISTING) as usize as u32);
        }
    }
}
