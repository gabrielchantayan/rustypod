//! `word_key_set_recycle_tree` — retailOS `FUN_083c099c` @ `0x083c099c`.
//!
//! Raw `osos.dec` establishes the exact 60-byte A32 extent
//! `0x083c099c..0x083c09d7`: `stmdb sp!, {r2,r3,r4,r5,r6,r7,r8,r9,sl,lr}` at
//! `0x083c09d8` starts the next independently linked function. Whole-image A32
//! branch decoding finds two inbound plain `bl` calls (`0x083c07a8` and the
//! recursive call at `0x083c09b4`) and no predicated `bl` forms. The body has
//! one plain recursive `bl` and no predicated calls. It depth-first recycles a
//! sibling chain: each node's child chain at `+0x0c` is processed first, then
//! the node is prepended to the word-key set's free-list head at `+0x04`; sibling
//! traversal uses `+0x08`.
//!
//! # Deliberate deviations
//!
//! Target pointers remain `u32` words rather than Rust pointers, preserving
//! the retail four-byte field layout on 64-bit host test builds.

/// Recycles `first_child` and every descendant into `word_key_set`'s free list.
///
/// `word_key_set` and all nonzero target-word node addresses must be valid,
/// aligned writable pointers. As in retailOS, `word_key_set` is not NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_key_set_recycle_tree")]
pub unsafe extern "C" fn word_key_set_recycle_tree(word_key_set: *mut u32, mut first_child: u32) {
    while first_child != 0 {
        let node = first_child as usize as *mut u32;
        unsafe { word_key_set_recycle_tree(word_key_set, core::ptr::read_volatile(node.add(3))) };
        let free_list_head = unsafe { core::ptr::read_volatile(word_key_set.add(1)) };
        first_child = unsafe { core::ptr::read_volatile(node.add(2)) };
        unsafe { core::ptr::write_volatile(node.add(3), free_list_head) };
        unsafe { core::ptr::write_volatile(word_key_set.add(1), node as usize as u32) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::word_key_set_recycle_tree;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const WORDS: usize = 0x1000;
    const SET: usize = 0;
    const EXISTING_FREE: usize = 8;
    const FIRST: usize = 16;
    const SECOND: usize = 24;
    const GRANDCHILD: usize = 32;
    const GRANDCHILD_SIBLING: usize = 40;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::WORD_KEY_SET_RECYCLE_TREE, WORDS * core::mem::size_of::<u32>())
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    fn slab() -> Option<*mut u32> {
        (*SLAB).map(|address| address as *mut u32)
    }

    #[test]
    fn leaves_free_list_unchanged_for_empty_tree() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(SET + 1).write(base.add(EXISTING_FREE) as usize as u32);
            word_key_set_recycle_tree(base.add(SET), 0);
            assert_eq!(base.add(SET + 1).read(), base.add(EXISTING_FREE) as usize as u32);
        }
    }

    #[test]
    fn recycles_tree_in_depth_first_order() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(SET + 1).write(base.add(EXISTING_FREE) as usize as u32);
            base.add(FIRST + 2).write(base.add(SECOND) as usize as u32);
            base.add(FIRST + 3).write(base.add(GRANDCHILD) as usize as u32);
            base.add(SECOND + 2).write(0);
            base.add(SECOND + 3).write(0);
            base.add(GRANDCHILD + 2).write(base.add(GRANDCHILD_SIBLING) as usize as u32);
            base.add(GRANDCHILD + 3).write(0);
            base.add(GRANDCHILD_SIBLING + 2).write(0);
            base.add(GRANDCHILD_SIBLING + 3).write(0);

            word_key_set_recycle_tree(base.add(SET), base.add(FIRST) as usize as u32);

            assert_eq!(base.add(SET + 1).read(), base.add(SECOND) as usize as u32);
            assert_eq!(base.add(SECOND + 3).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(FIRST + 3).read(), base.add(GRANDCHILD_SIBLING) as usize as u32);
            assert_eq!(base.add(GRANDCHILD_SIBLING + 3).read(), base.add(GRANDCHILD) as usize as u32);
            assert_eq!(base.add(GRANDCHILD + 3).read(), base.add(EXISTING_FREE) as usize as u32);
        }
    }
}
