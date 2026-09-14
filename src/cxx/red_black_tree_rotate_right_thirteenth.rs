//! Generic C++ red-black-tree right rotation — original: `FUN_083bd570` at
//! load address `0x083bd570`.
//!
//! Raw `osos.dec` establishes the exact 84-byte extent: 21 ARM words from
//! `ldr r2,[r1,#8]` at `0x083bd570` through `bx lr` at `0x083bd5c0`; the next
//! separately linked function begins at `0x083bd5c4`. Decoding every aligned
//! ARM B/BL-immediate word in `osos.dec` finds five inbound direct calls: four
//! unconditional `bl` at `0x083bd8bc`, `0x083bd934`, `0x083bda20`, and
//! `0x083bddf0`, plus predicated `bleq` at `0x083bde40`; there are no direct
//! tail-B callers.
//!
//! The left child replaces the pivot under its old parent (or the header root
//! slot), its right subtree becomes the pivot's left subtree, and the pivot
//! becomes that child's right subtree. Deliberate deviations: none; links use
//! target-width `u32` words so the 32-bit target layout and host fixtures are
//! identical.

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
/// Original: `FUN_083bd570` at load address `0x083bd570` (84 bytes; five
/// inbound `bl` sites: four unconditional and one `bleq`).
///
/// # Safety
///
/// `tree` must contain a valid header word at +0x10; `node` and its non-null
/// left child must be readable and writable [`RedBlackTreeNode`] records. All
/// parent and child links traversed by the rotation must be valid aligned
/// target-width node words. The retail function performs no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_rotate_right_thirteenth")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_rotate_right_thirteenth(
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
        if (*parent).right == node_word(node) {
            (*parent).right = node_word(left);
        } else {
            (*parent).left = node_word(left);
        }
    }
    (*left).right = node_word(node);
    (*node).parent = node_word(left);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{red_black_tree_rotate_right_thirteenth, RedBlackTree, RedBlackTreeNode};
    use core::ptr;
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_ROTATE_RIGHT_THIRTEENTH,
            0x1000,
        )
        .map(|p| p as usize)
    });

    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    unsafe fn word(node: *mut RedBlackTreeNode) -> u32 {
        node as usize as u32
    }

    unsafe fn node(base: *mut u8, index: usize) -> *mut RedBlackTreeNode {
        base.add(0x100 + index * core::mem::size_of::<RedBlackTreeNode>()).cast()
    }

    unsafe fn initialize(
        node: *mut RedBlackTreeNode,
        parent: *mut RedBlackTreeNode,
        left: *mut RedBlackTreeNode,
        right: *mut RedBlackTreeNode,
    ) {
        node.write(RedBlackTreeNode {
            color: 0x5a5a_5a5a,
            parent: word(parent),
            left: word(left),
            right: word(right),
        });
    }

    unsafe fn initialize_tree(base: *mut u8, header: *mut RedBlackTreeNode) -> *mut RedBlackTree {
        let tree = base.add(0x20).cast::<RedBlackTree>();
        tree.write(RedBlackTree {
            _opaque: [0; 0x10],
            header: word(header),
        });
        tree
    }

    #[test]
    fn rotates_root_and_both_parent_child_slots() {
        let Some(base) = try_slab() else {
            crate::testing::note_missing_u32_fixture("red_black_tree_rotate_right_thirteenth");
            return;
        };

        unsafe {
            // Root pivot: transfer the left child's right subtree to the pivot.
            ptr::write_bytes(base, 0, 0x1000);
            let header = node(base, 0);
            let pivot = node(base, 1);
            let promoted = node(base, 2);
            let middle = node(base, 3);
            let preserved_right = node(base, 4);
            initialize(header, pivot, ptr::null_mut(), preserved_right);
            initialize(pivot, header, promoted, preserved_right);
            initialize(promoted, pivot, ptr::null_mut(), middle);
            initialize(middle, promoted, ptr::null_mut(), ptr::null_mut());
            initialize(preserved_right, pivot, ptr::null_mut(), ptr::null_mut());
            let tree = initialize_tree(base, header);
            red_black_tree_rotate_right_thirteenth(tree, pivot);
            assert_eq!((*header).parent, word(promoted));
            assert_eq!((*promoted).parent, word(header));
            assert_eq!((*promoted).right, word(pivot));
            assert_eq!((*pivot).parent, word(promoted));
            assert_eq!((*pivot).left, word(middle));
            assert_eq!((*middle).parent, word(pivot));
            assert_eq!((*pivot).right, word(preserved_right));

            // A pivot in its parent's left slot must replace exactly that slot.
            ptr::write_bytes(base, 0, 0x1000);
            let header = node(base, 0);
            let parent = node(base, 1);
            let pivot = node(base, 2);
            let promoted = node(base, 3);
            let sibling = node(base, 4);
            initialize(header, parent, pivot, sibling);
            initialize(parent, header, pivot, sibling);
            initialize(pivot, parent, promoted, ptr::null_mut());
            initialize(promoted, pivot, ptr::null_mut(), ptr::null_mut());
            initialize(sibling, parent, ptr::null_mut(), ptr::null_mut());
            let tree = initialize_tree(base, header);
            red_black_tree_rotate_right_thirteenth(tree, pivot);
            assert_eq!((*header).parent, word(parent));
            assert_eq!((*parent).left, word(promoted));
            assert_eq!((*parent).right, word(sibling));
            assert_eq!((*promoted).parent, word(parent));
            assert_eq!((*promoted).right, word(pivot));
            assert_eq!((*pivot).parent, word(promoted));

            // A pivot in its parent's right slot takes the opposite branch.
            ptr::write_bytes(base, 0, 0x1000);
            let header = node(base, 0);
            let parent = node(base, 1);
            let pivot = node(base, 2);
            let promoted = node(base, 3);
            let sibling = node(base, 4);
            initialize(header, parent, sibling, pivot);
            initialize(parent, header, sibling, pivot);
            initialize(pivot, parent, promoted, ptr::null_mut());
            initialize(promoted, pivot, ptr::null_mut(), ptr::null_mut());
            initialize(sibling, parent, ptr::null_mut(), ptr::null_mut());
            let tree = initialize_tree(base, header);
            red_black_tree_rotate_right_thirteenth(tree, pivot);
            assert_eq!((*header).parent, word(parent));
            assert_eq!((*parent).left, word(sibling));
            assert_eq!((*parent).right, word(promoted));
            assert_eq!((*promoted).parent, word(parent));
            assert_eq!((*promoted).right, word(pivot));
            assert_eq!((*pivot).parent, word(promoted));
        }
    }
}
