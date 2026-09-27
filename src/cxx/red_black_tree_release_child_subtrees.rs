//! `red_black_tree_release_child_subtrees` — retailOS `FUN_083c4a84` @
//! `0x083c4a84` (64 bytes).
//!
//! Raw `osos.dec` establishes the exact sixteen-word A32 extent from `push
//! {r4,r5,r6,lr}` at `0x083c4a84` through `pop {r4,r5,r6,pc}` at
//! `0x083c4ac0`; `push {r2,r3,r4,r5,r6,r7,r8,r9,sl,lr}` at `0x083c4ac4`
//! begins the next real function. The body has exactly two unconditional plain
//! direct `bl` instructions—the recursive call at `0x083c4a9c` and
//! `red_black_tree_root_replace`/`FUN_083c4150` at `0x083c4ab0`—and no
//! predicated `bl` instructions.
//!
//! Algorithm: postorder-traverse each node's child chain at word +3, snapshot
//! its successor at word +2, then move the node to `chain`'s head at word +1
//! through `red_black_tree_root_replace`, which destroys its two string fields.
//! Deliberate deviation: target pointers remain `u32` words so field offsets
//! remain valid in 64-bit host fixtures; the recursive ARM `bl` is Rust
//! recursion.

use crate::cxx::red_black_tree_root_replace::red_black_tree_root_replace;

const NEXT: usize = 2;
const FIRST_CHILD: usize = 3;


/// Releases a successor chain and every child subtree into `chain`'s root link.
///
/// # Safety
///
/// `chain` must have a writable word at +1. Each nonzero target-word node must
/// be valid for the successor and child words at +2/+3 and for
/// `red_black_tree_root_replace`'s accessed fields.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_release_child_subtrees")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_release_child_subtrees(chain: *mut u32, mut node: u32) {
    while node != 0 {
        let current = node as usize as *mut u32;
        unsafe { red_black_tree_release_child_subtrees(chain, current.add(FIRST_CHILD).read()) };
        node = unsafe { current.add(NEXT).read() };
        unsafe { red_black_tree_root_replace(chain, current, 1) };
    }
}

#[cfg(test)]
type ReleaseNode = unsafe extern "C" fn(*mut u32, *mut u32, u32);

#[cfg(test)]
unsafe fn red_black_tree_release_child_subtrees_with(
    chain: *mut u32,
    mut node: u32,
    release_node: ReleaseNode,
) {
    while node != 0 {
        let current = node as usize as *mut u32;
        unsafe { red_black_tree_release_child_subtrees_with(chain, current.add(FIRST_CHILD).read(), release_node) };
        node = unsafe { current.add(NEXT).read() };
        unsafe { release_node(chain, current, 1) };
    }
}
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static RELEASED_NODES: Mutex<std::vec::Vec<u32>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn release_node(chain: *mut u32, node: *mut u32, destroy_strings: u32) {
        assert_eq!(destroy_strings, 1);
        RELEASED_NODES.lock().push(node as usize as u32);
        unsafe { node.add(3).write(chain.add(1).read()) };
        unsafe { chain.add(1).write(node as usize as u32) };
    }

    #[test]
    fn releases_children_before_each_successor_and_prepends_them() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_RELEASE_CHILD_SUBTREES, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let chain = slab.cast::<u32>();
        let first = unsafe { chain.add(16) };
        let second = unsafe { chain.add(32) };
        let first_child = unsafe { chain.add(48) };
        let second_child = unsafe { chain.add(64) };
        unsafe {
            RELEASED_NODES.lock().clear();
            chain.add(1).write(0xfeed_beef);
            first.add(NEXT).write(second as usize as u32);
            first.add(FIRST_CHILD).write(first_child as usize as u32);
            second.add(NEXT).write(0);
            second.add(FIRST_CHILD).write(second_child as usize as u32);
            first_child.add(NEXT).write(0);
            first_child.add(FIRST_CHILD).write(0);
            second_child.add(NEXT).write(0);
            second_child.add(FIRST_CHILD).write(0);
            red_black_tree_release_child_subtrees_with(chain, first as usize as u32, release_node);
        }
        assert_eq!(*RELEASED_NODES.lock(), [first_child as usize as u32, first as usize as u32, second_child as usize as u32, second as usize as u32]);
        assert_eq!(unsafe { chain.add(1).read() }, second as usize as u32);
        assert_eq!(unsafe { second.add(3).read() }, second_child as usize as u32);
        assert_eq!(unsafe { second_child.add(3).read() }, first as usize as u32);
        assert_eq!(unsafe { first.add(3).read() }, first_child as usize as u32);
        assert_eq!(unsafe { first_child.add(3).read() }, 0xfeed_beef);
    }

    #[test]
    fn leaves_chain_unchanged_for_an_empty_successor_chain() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_RELEASE_CHILD_SUBTREES_EMPTY, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let chain = slab.cast::<u32>();
        unsafe {
            RELEASED_NODES.lock().clear();
            chain.add(1).write(0x1234_5678);
            red_black_tree_release_child_subtrees_with(chain, 0, release_node);
        }
        assert!(RELEASED_NODES.lock().is_empty());
        assert_eq!(unsafe { chain.add(1).read() }, 0x1234_5678);
    }
}
