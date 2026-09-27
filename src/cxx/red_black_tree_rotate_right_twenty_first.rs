//! Generic C++ red-black-tree right rotation — original: `FUN_083c2d60` at
//! load address `0x083c2d60`.
//!
//! Raw `osos.dec` establishes the exact 80-byte extent: 20 ARM words from
//! `ldr r2,[r1,#8]` at `0x083c2d60` through `bx lr` at `0x083c2db0`;
//! `0x083c2db4` begins the next real function. Raw whole-image branch decoding
//! verifies two inbound direct calls: plain `bl` at `0x083c306c` and predicated
//! `bleq` at `0x083c30bc`. The caller selects the pivot before either call, so
//! this rotation deliberately retains the retail routine's lack of NULL guards.
//!
//! The left child replaces the pivot under its old parent (or the header root
//! slot), its right subtree becomes the pivot's left subtree, and the pivot
//! becomes that child's right subtree. Deliberate deviations: none; links use
//! target-width `u32` words so the target layout and host fixtures agree.

use super::red_black_tree_increment::RedBlackTreeNode;
use super::red_black_tree_rotate_right::RedBlackTree;

#[inline(always)]
unsafe fn node_from_word(address: u32) -> *mut RedBlackTreeNode {
    address as usize as *mut RedBlackTreeNode
}

#[inline(always)]
fn node_word(node: *mut RedBlackTreeNode) -> u32 {
    node as usize as u32
}

/// Rotates `node` right in `tree`.
///
/// Original: `FUN_083c2d60` at load address `0x083c2d60` (80 bytes; two
/// inbound `bl` sites: one unconditional and one `bleq`).
///
/// # Safety
///
/// `tree` must contain a valid header word at +0x10; `node` and its non-null
/// left child must be readable and writable [`RedBlackTreeNode`] records. All
/// parent and child links traversed by the rotation must be valid aligned
/// target-width node words. The retail function performs no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_rotate_right_twenty_first")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_rotate_right_twenty_first(
    tree: *mut RedBlackTree,
    node: *mut RedBlackTreeNode,
) {
    let left = node_from_word((*node).left);
    let middle = (*left).right;
    (*node).left = middle;
    if middle != 0 {
        (*node_from_word(middle)).parent = node_word(node);
    }

    (*left).parent = (*node).parent;
    let header = node_from_word((*tree).header);
    if (*header).parent == node_word(node) {
        (*header).parent = node_word(left);
    } else {
        let parent = node_from_word((*node).parent);
        if (*parent).left == node_word(node) {
            (*parent).left = node_word(left);
        } else {
            (*parent).right = node_word(left);
        }
    }
    (*left).right = node_word(node);
    (*node).parent = node_word(left);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{red_black_tree_rotate_right_twenty_first, RedBlackTree, RedBlackTreeNode};
    use core::ptr;
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_ROTATE_RIGHT_TWENTY_FIRST,
            0x1000,
        )
        .map(|p| p as usize)
    });

    fn word(node: *mut RedBlackTreeNode) -> u32 {
        node as usize as u32
    }

    unsafe fn node(base: *mut u8, index: usize) -> *mut RedBlackTreeNode {
        base.add(0x100 + index * core::mem::size_of::<RedBlackTreeNode>()).cast()
    }

    unsafe fn initialize(node: *mut RedBlackTreeNode, parent: *mut RedBlackTreeNode, left: *mut RedBlackTreeNode, right: *mut RedBlackTreeNode) {
        node.write(RedBlackTreeNode { color: 0x5a5a_5a5a, parent: word(parent), left: word(left), right: word(right) });
    }

    #[test]
    fn rotates_root_and_parent_slots() {
        let Some(base) = (*SLAB).map(|p| p as *mut u8) else {
            crate::testing::note_missing_u32_fixture("red_black_tree_rotate_right_twenty_first");
            return;
        };
        unsafe {
            for pivot_is_left in [true, false] {
                ptr::write_bytes(base, 0, 0x1000);
                let header = node(base, 0); let parent = node(base, 1); let pivot = node(base, 2);
                let promoted = node(base, 3); let middle = node(base, 4); let sibling = node(base, 5);
                initialize(header, parent, ptr::null_mut(), ptr::null_mut());
                initialize(parent, header, if pivot_is_left { pivot } else { sibling }, if pivot_is_left { sibling } else { pivot });
                initialize(pivot, parent, promoted, ptr::null_mut());
                initialize(promoted, pivot, ptr::null_mut(), middle);
                initialize(middle, promoted, ptr::null_mut(), ptr::null_mut());
                initialize(sibling, parent, ptr::null_mut(), ptr::null_mut());
                let tree = base.add(0x20).cast::<RedBlackTree>();
                tree.write(RedBlackTree { _opaque: [0; 0x10], header: word(header) });
                red_black_tree_rotate_right_twenty_first(tree, pivot);
                assert_eq!((*header).parent, word(parent));
                assert_eq!((*promoted).parent, word(parent));
                assert_eq!((*promoted).right, word(pivot));
                assert_eq!((*pivot).parent, word(promoted));
                assert_eq!((*pivot).left, word(middle));
                assert_eq!((*middle).parent, word(pivot));
                assert_eq!(if pivot_is_left { (*parent).left } else { (*parent).right }, word(promoted));
                assert_eq!(if pivot_is_left { (*parent).right } else { (*parent).left }, word(sibling));
            }
        }
    }
}
