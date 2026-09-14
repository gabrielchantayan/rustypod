//! Generic C++ red-black-tree left rotation — original: `FUN_083ceccc` at
//! load address `0x083ceccc`.
//!
//! Raw `osos.dec` establishes the exact 84-byte extent: 21 ARM words from
//! `ldr r2,[r1,#0xc]` at `0x083ceccc` through `bx lr` at `0x083ced1c`; the
//! separately linked right-rotation sibling begins at `0x083ced20`. Decoding
//! every aligned ARM B/BL-immediate word in `osos.dec` finds five inbound
//! direct calls: four unconditional `bl` at `0x083cf008`, `0x083cf0a8`,
//! `0x083cf194`, and `0x083cf614`, plus a predicated `bleq` at `0x083cf57c`.
//! The predicated site reaches this no-guard rotation only after its caller
//! has selected the right child as the pivot; all callers therefore supply a
//! non-null pivot with a non-null right child.
//!
//! The right child replaces the pivot under its old parent (or the header root
//! slot), its left subtree becomes the pivot's right subtree, and the pivot
//! becomes that child's left subtree. Deliberate deviations: none; links use
//! target-width `u32` words so the 32-bit target layout and host fixtures are
//! identical.
//!
//! The byte-identical `FUN_083c5a5c` at load address `0x083c5a5c` is a
//! ported ledger alias of this implementation; its five direct callers have
//! the same four `bl` plus one `bleq` split.
//!
//! `FUN_083ba024` at load address `0x083ba024` is an 84-byte, byte-identical
//! alias of this port. Raw branch decoding finds five direct callers: four
//! unconditional `bl` at `0x083ba360`, `0x083ba400`, `0x083ba4f0`, and
//! `0x083ba97c`, plus `bleq` at `0x083ba8e4`. The conditional caller selects
//! the pivot before reaching this no-guard rotation; the shared tests cover its
//! root and both parent-child-slot cases. Deliberate deviations: none.
//!
//! `FUN_083c4e14` at load address `0x083c4e14` is another byte-identical
//! ported alias. Raw `osos.dec` gives it an 80-byte extent (through `bx lr` at
//! `0x083c4e60`); Ghidra's 84-byte size includes the right-rotation sibling's
//! first instruction at `0x083c4e64`. It has five inbound direct call sites:
//! four `bl` (`0x083c51f4`, `0x083c5294`, `0x083c5384`, and `0x083c589c`) and
//! one `bleq` (`0x083c5804`). Its no-guard left-rotation algorithm and
//! target-width-link representation have no deliberate deviations from this
//! implementation.
//!
//! `FUN_083c4188` at load address `0x083c4188` is byte-identical to this
//! implementation: 84 bytes (21 ARM words) through `bx lr` at `0x083c41d8`,
//! followed by the separately linked right-rotation sibling at `0x083c41dc`.
//! Its five verified direct call sites comprise unconditional `bl` at
//! `0x083c44c4`, `0x083c4564`, `0x083c4654`, and `0x083c4c50`, plus a
//! predicated `bleq` at `0x083c4bb8`; there are no direct tail-B callers.
//! As with the primary body, callers have selected the pivot's right child
//! before invoking this no-guard rotation. It deliberately reuses this
//! dispatch seam; the shared host test exercises every parent-placement branch
//! and the transferred middle subtree.

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

/// Rotates `node` left in `tree`.
///
/// Original: `FUN_083ceccc` at load address `0x083ceccc` (84 bytes; five
/// inbound `bl` sites: four unconditional and one `bleq`).
///
/// # Safety
///
/// `tree` must contain a valid header word at +0x10; `node` and its non-null
/// right child must be readable and writable [`RedBlackTreeNode`] records. All
/// parent and child links traversed by the rotation must be valid aligned
/// target-width node words. The retail function performs no NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_rotate_left")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_rotate_left(
    tree: *mut RedBlackTree,
    node: *mut RedBlackTreeNode,
) {
    let right = node_from_word((*node).right);
    let middle = (*right).left;
    (*node).right = middle;
    if middle != 0 {
        (*node_from_word(middle)).parent = node_word(node);
    }

    (*right).parent = (*node).parent;
    let header = node_from_word((*tree).header);
    if (*header).parent == node_word(node) {
        (*header).parent = node_word(right);
    } else {
        let parent = node_from_word((*node).parent);
        if (*parent).left == node_word(node) {
            (*parent).left = node_word(right);
        } else {
            (*parent).right = node_word(right);
        }
    }
    (*right).left = node_word(node);
    (*node).parent = node_word(right);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{red_black_tree_rotate_left, RedBlackTree, RedBlackTreeNode};
    use core::ptr;
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_ROTATE_LEFT,
            0x1000,
        )
        .map(|p| p as usize)
    });

    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    fn word(node: *mut RedBlackTreeNode) -> u32 {
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
            crate::testing::note_missing_u32_fixture("red_black_tree_rotate_left");
            return;
        };

        unsafe {
            // Root pivot: transfer the right child's left subtree to the pivot.
            ptr::write_bytes(base, 0, 0x1000);
            let header = node(base, 0);
            let pivot = node(base, 1);
            let promoted = node(base, 2);
            let middle = node(base, 3);
            let preserved_left = node(base, 4);
            initialize(header, pivot, preserved_left, ptr::null_mut());
            initialize(pivot, header, preserved_left, promoted);
            initialize(promoted, pivot, middle, ptr::null_mut());
            initialize(middle, promoted, ptr::null_mut(), ptr::null_mut());
            initialize(preserved_left, pivot, ptr::null_mut(), ptr::null_mut());
            let tree = initialize_tree(base, header);
            red_black_tree_rotate_left(tree, pivot);
            assert_eq!((*header).parent, word(promoted));
            assert_eq!((*promoted).parent, word(header));
            assert_eq!((*promoted).left, word(pivot));
            assert_eq!((*pivot).parent, word(promoted));
            assert_eq!((*pivot).right, word(middle));
            assert_eq!((*middle).parent, word(pivot));
            assert_eq!((*pivot).left, word(preserved_left));

            // A pivot in its parent's right slot must replace exactly that slot.
            ptr::write_bytes(base, 0, 0x1000);
            let header = node(base, 0);
            let parent = node(base, 1);
            let pivot = node(base, 2);
            let promoted = node(base, 3);
            let sibling = node(base, 4);
            initialize(header, parent, sibling, pivot);
            initialize(parent, header, sibling, pivot);
            initialize(pivot, parent, ptr::null_mut(), promoted);
            initialize(promoted, pivot, ptr::null_mut(), ptr::null_mut());
            initialize(sibling, parent, ptr::null_mut(), ptr::null_mut());
            let tree = initialize_tree(base, header);
            red_black_tree_rotate_left(tree, pivot);
            assert_eq!((*header).parent, word(parent));
            assert_eq!((*parent).right, word(promoted));
            assert_eq!((*parent).left, word(sibling));
            assert_eq!((*promoted).parent, word(parent));
            assert_eq!((*promoted).left, word(pivot));
            assert_eq!((*pivot).parent, word(promoted));
            assert_eq!((*pivot).right, 0);

            // A pivot in its parent's left slot takes the opposite branch.
            ptr::write_bytes(base, 0, 0x1000);
            let header = node(base, 0);
            let parent = node(base, 1);
            let pivot = node(base, 2);
            let promoted = node(base, 3);
            let sibling = node(base, 4);
            initialize(header, parent, pivot, sibling);
            initialize(parent, header, pivot, sibling);
            initialize(pivot, parent, ptr::null_mut(), promoted);
            initialize(promoted, pivot, ptr::null_mut(), ptr::null_mut());
            initialize(sibling, parent, ptr::null_mut(), ptr::null_mut());
            let tree = initialize_tree(base, header);
            red_black_tree_rotate_left(tree, pivot);
            assert_eq!((*header).parent, word(parent));
            assert_eq!((*parent).left, word(promoted));
            assert_eq!((*parent).right, word(sibling));
            assert_eq!((*promoted).parent, word(parent));
            assert_eq!((*promoted).left, word(pivot));
            assert_eq!((*pivot).parent, word(promoted));
        }
    }
}
