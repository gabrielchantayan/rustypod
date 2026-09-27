//! `tree_children_flatten_release_strings_083c3e44` — original:
//! `FUN_083c3e44` @ `0x083c3e44` (68 bytes).
//!
//! Raw `osos.dec` establishes the exact 68-byte A32 extent
//! `0x083c3e44..0x083c3e87`: the next independently linked function starts
//! with `push {r2,r3,r4,r5,r6,r7,r8,r9,sl,lr}` at `0x083c3e88`. The body has
//! two unconditional plain `bl` instructions—its recursive call at
//! `0x083c3e5c` and `cxx_string_release` @ `0x083d8b04` at `0x083c3e70`—and
//! no predicated `bl`. It has two inbound plain `bl` sites: `0x083c3c44` and
//! its recursive call; there are no predicated inbound calls.
//!
//! Algorithm: depth-first flatten a sibling chain by first flattening each
//! node's child chain at `+0x0c`, releasing that node's COW string slot at
//! `+0x10`, then prepending the node to the parent head at `+0x04`. Siblings
//! are followed through `+0x08`.
//!
//! # Deliberate deviations
//!
//! Target pointers remain `u32` words, preserving retailOS's four-byte field
//! layout on 64-bit host test builds. The host-only seam records release order
//! without dereferencing synthetic COW string storage.

use crate::cxx::string::cxx_string_release;

#[cfg(test)]
type StringRelease = unsafe extern "C" fn(*mut *mut u8);

const PARENT_HEAD: usize = 1;
const NODE_NEXT_SIBLING: usize = 2;
const NODE_FIRST_CHILD: usize = 3;
const NODE_STRING: usize = 4;

/// Depth-first flattens `first_child` into `parent`'s head link, releasing each
/// node's COW string slot after its descendants and before it is prepended.
///
/// `parent` and every nonzero target-word node address must be valid aligned,
/// writable pointers. As in retailOS, `parent` is not NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tree_children_flatten_release_strings_083c3e44")]
pub unsafe extern "C" fn tree_children_flatten_release_strings_083c3e44(
    parent: *mut u32,
    mut first_child: u32,
) {
    while first_child != 0 {
        let node = first_child as usize as *mut u32;
        unsafe {
            tree_children_flatten_release_strings_083c3e44(
                parent,
                core::ptr::read_volatile(node.add(NODE_FIRST_CHILD)),
            );
            let next_sibling = core::ptr::read_volatile(node.add(NODE_NEXT_SIBLING));
            core::ptr::write_volatile(node.add(NODE_FIRST_CHILD), core::ptr::read_volatile(parent.add(PARENT_HEAD)));
            cxx_string_release(node.add(NODE_STRING).cast());
            core::ptr::write_volatile(parent.add(PARENT_HEAD), node as usize as u32);
            first_child = next_sibling;
        }
    }
}

#[cfg(test)]
#[inline(always)]
unsafe fn tree_children_flatten_release_strings_083c3e44_with(
    parent: *mut u32,
    mut first_child: u32,
    release_string: StringRelease,
) {
    while first_child != 0 {
        let node = first_child as usize as *mut u32;
        unsafe {
            tree_children_flatten_release_strings_083c3e44_with(
                parent,
                core::ptr::read_volatile(node.add(NODE_FIRST_CHILD)),
                release_string,
            );
            let next_sibling = core::ptr::read_volatile(node.add(NODE_NEXT_SIBLING));
            core::ptr::write_volatile(node.add(NODE_FIRST_CHILD), core::ptr::read_volatile(parent.add(PARENT_HEAD)));
            release_string(node.add(NODE_STRING).cast());
            core::ptr::write_volatile(parent.add(PARENT_HEAD), node as usize as u32);
            first_child = next_sibling;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    use std::vec::Vec;

    const WORDS: usize = 0x1000;
    const PARENT: usize = 0;
    const EXISTING: usize = 8;
    const FIRST: usize = 16;
    const SECOND: usize = 24;
    const GRANDCHILD: usize = 32;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(
            hints::TREE_CHILDREN_FLATTEN_RELEASE_STRINGS_083C3E44,
            WORDS * core::mem::size_of::<u32>(),
        )
        .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static RELEASES: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn record_string_release(slot: *mut *mut u8) {
        RELEASES.lock().push(slot as usize);
    }

    fn slab() -> Option<*mut u32> {
        (*SLAB).map(|address| address as *mut u32)
    }

    #[test]
    fn leaves_existing_head_and_releases_nothing_for_empty_chain() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        RELEASES.lock().clear();
        unsafe {
            base.add(PARENT + PARENT_HEAD).write(base.add(EXISTING) as usize as u32);
            tree_children_flatten_release_strings_083c3e44_with(base.add(PARENT), 0, record_string_release);
            assert_eq!(base.add(PARENT + PARENT_HEAD).read(), base.add(EXISTING) as usize as u32);
        }
        assert!(RELEASES.lock().is_empty());
    }

    #[test]
    fn releases_postorder_and_prepends_depth_first_chain() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        RELEASES.lock().clear();
        unsafe {
            base.add(PARENT + PARENT_HEAD).write(base.add(EXISTING) as usize as u32);
            base.add(FIRST + NODE_NEXT_SIBLING).write(base.add(SECOND) as usize as u32);
            base.add(FIRST + NODE_FIRST_CHILD).write(base.add(GRANDCHILD) as usize as u32);
            base.add(SECOND + NODE_NEXT_SIBLING).write(0);
            base.add(SECOND + NODE_FIRST_CHILD).write(0);
            base.add(GRANDCHILD + NODE_NEXT_SIBLING).write(0);
            base.add(GRANDCHILD + NODE_FIRST_CHILD).write(0);

            tree_children_flatten_release_strings_083c3e44_with(
                base.add(PARENT),
                base.add(FIRST) as usize as u32,
                record_string_release,
            );

            assert_eq!(base.add(PARENT + PARENT_HEAD).read(), base.add(SECOND) as usize as u32);
            assert_eq!(base.add(SECOND + NODE_FIRST_CHILD).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(FIRST + NODE_FIRST_CHILD).read(), base.add(GRANDCHILD) as usize as u32);
            assert_eq!(base.add(GRANDCHILD + NODE_FIRST_CHILD).read(), base.add(EXISTING) as usize as u32);
        }
        assert_eq!(
            RELEASES.lock().as_slice(),
            [
                unsafe { base.add(GRANDCHILD + NODE_STRING) as usize },
                unsafe { base.add(FIRST + NODE_STRING) as usize },
                unsafe { base.add(SECOND + NODE_STRING) as usize },
            ],
        );
    }
}
