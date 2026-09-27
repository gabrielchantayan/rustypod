//! Recycles an equality-keyed red-black-tree subtree — original:
//! `FUN_083bf218` @ `0x083bf218`.
//!
//! Raw `osos.dec` establishes the exact 60-byte A32 extent
//! `0x083bf218..0x083bf253`: the next independently entered function begins
//! with `stmdb sp!, {r2-r9,sl,lr}` at `0x083bf254`. There are two verified
//! inbound plain `bl` call sites (0x083bf018 and the recursive call at
//! 0x083bf230) and zero predicated `bl` forms. The body has one plain
//! recursive `bl` and no predicated calls. It depth-first recycles each
//! node's right subtree at `+0x0c`, then prepends the node to the tree pool's
//! free-list head at `+0x04`; traversal continues through the saved left link
//! at `+0x08`.
//!
//! # Deliberate deviations
//!
//! Target pointers remain `u32` words rather than Rust pointers, preserving
//! retail four-byte field offsets on 64-bit host test builds.

/// Recycles `node` and its descendants into `tree`'s free-node list.
///
/// Original: `FUN_083bf218` at load address `0x083bf218` (60 bytes; two
/// inbound plain `bl` calls and no predicated inbound calls).
///
/// # Safety
///
/// `tree` must have a writable target-width free-list word at `+0x04`. Every
/// nonzero node link must designate writable, aligned storage with right and
/// left links at `+0x0c` and `+0x08`. RetailOS performs no NULL check on
/// `tree` and no validation of nonzero node links.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.equal_key_tree_recycle_subtree")]
pub unsafe extern "C" fn equal_key_tree_recycle_subtree(tree: *mut u32, mut node: u32) {
    while node != 0 {
        let current = node as usize as *mut u32;
        unsafe { equal_key_tree_recycle_subtree(tree, core::ptr::read_volatile(current.add(3))) };
        let free_head = unsafe { core::ptr::read_volatile(tree.add(1)) };
        node = unsafe { core::ptr::read_volatile(current.add(2)) };
        unsafe { core::ptr::write_volatile(current.add(3), free_head) };
        unsafe { core::ptr::write_volatile(tree.add(1), current as usize as u32) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::equal_key_tree_recycle_subtree;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const WORDS: usize = 0x1000;
    const TREE: usize = 0;
    const EXISTING: usize = 8;
    const ROOT: usize = 16;
    const LEFT: usize = 24;
    const RIGHT: usize = 32;
    const RIGHT_LEFT: usize = 40;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::EQUAL_KEY_TREE_RECYCLE_SUBTREE, WORDS * core::mem::size_of::<u32>())
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    fn slab() -> Option<*mut u32> {
        (*SLAB).map(|address| address as *mut u32)
    }

    #[test]
    fn leaves_free_list_unchanged_for_a_null_subtree() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(TREE + 1).write(base.add(EXISTING) as usize as u32);
            equal_key_tree_recycle_subtree(base.add(TREE), 0);
            assert_eq!(base.add(TREE + 1).read(), base.add(EXISTING) as usize as u32);
        }
    }

    #[test]
    fn recycles_right_subtrees_before_nodes_and_saved_left_chain() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(TREE + 1).write(base.add(EXISTING) as usize as u32);
            base.add(ROOT + 2).write(base.add(LEFT) as usize as u32);
            base.add(ROOT + 3).write(base.add(RIGHT) as usize as u32);
            base.add(LEFT + 2).write(0);
            base.add(LEFT + 3).write(0);
            base.add(RIGHT + 2).write(base.add(RIGHT_LEFT) as usize as u32);
            base.add(RIGHT + 3).write(0);
            base.add(RIGHT_LEFT + 2).write(0);
            base.add(RIGHT_LEFT + 3).write(0);

            equal_key_tree_recycle_subtree(base.add(TREE), base.add(ROOT) as usize as u32);

            assert_eq!(base.add(TREE + 1).read(), base.add(LEFT) as usize as u32);
            assert_eq!(base.add(LEFT + 3).read(), base.add(ROOT) as usize as u32);
            assert_eq!(base.add(ROOT + 3).read(), base.add(RIGHT_LEFT) as usize as u32);
            assert_eq!(base.add(RIGHT_LEFT + 3).read(), base.add(RIGHT) as usize as u32);
            assert_eq!(base.add(RIGHT + 3).read(), base.add(EXISTING) as usize as u32);
        }
    }
}
