//! Red-black tree in-order iterator increment — original: `FUN_083b580c` @
//! `0x083b580c`.
//!
//! Raw `osos.dec` runs for **88 bytes**, `0x083b580c..0x083b5860`; the next
//! separately linked sibling begins at `0x083b5864`. Decoding every ARM B/BL
//! word finds exactly **6 direct, unconditional `bl` callers** at 0x0825b890,
//! 0x0825b940, 0x0825bb30, 0x0825bbc8, 0x0825bc70, and 0x0825bcec. There are
//! no predicated calls, direct `b` transfers, or aligned data-word references.
//!
//! The function returns the original node held by `cursor` and advances the
//! cursor to its in-order successor. A right child selects that subtree's
//! leftmost node. Otherwise it climbs parent links while leaving right-child
//! edges, then selects the first ancestor reached from a left-child edge; the
//! sentinel case is preserved by the final right-link comparison.
//!
//! Deliberate deviations: none. Links remain target-width `u32` words, rather
//! than host pointers, so their 32-bit `repr(C)` layout and host fixtures match
//! the firmware exactly.

/// Base node layout used by the C++ red-black tree implementation.
///
/// The color word is opaque here. The remaining fields are target-width
/// addresses: parent at +0x04, left child at +0x08, and right child at +0x0c.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreeNode {
    pub color: u32,
    pub parent: u32,
    pub left: u32,
    pub right: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreeNode, parent)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreeNode, left)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreeNode, right)];
const _: [u8; 0x10] = [0; core::mem::size_of::<RedBlackTreeNode>()];

#[inline(always)]
unsafe fn node_from_word(address: u32) -> *mut RedBlackTreeNode {
    address as usize as *mut RedBlackTreeNode
}

/// Advances `cursor` to the next node in red-black-tree in-order traversal.
/// Original: `FUN_083b580c` @ `0x083b580c` (88 bytes; 6 direct,
/// unconditional `bl` callers).
///
/// Returns the node that was in `*cursor` before the advance.
///
/// # Safety
///
/// `cursor` must be writable and initially contain a valid non-NULL
/// [`RedBlackTreeNode`] address. Every link traversed by the normal tree and
/// sentinel invariants must likewise designate a readable aligned node. This
/// matches the original's absence of NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_increment(cursor: *mut u32) -> u32 {
    let original = cursor.read();
    let mut current = node_from_word(original);
    let mut next = (*current).right;

    if next != 0 {
        cursor.write(next);
        current = node_from_word(next);
        next = (*current).left;
        while next != 0 {
            cursor.write(next);
            current = node_from_word(next);
            next = (*current).left;
        }
    } else {
        cursor.write(original);
        next = (*current).parent;
        loop {
            current = node_from_word(next);
            if (*current).right != cursor.read() {
                break;
            }
            cursor.write(next);
            next = (*current).parent;
        }
        current = node_from_word(cursor.read());
        if (*current).right != next {
            cursor.write(next);
        }
    }

    original
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{red_black_tree_increment, RedBlackTreeNode};
    use core::ptr;
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::RED_BLACK_TREE_INCREMENT, 0x1000)
            .map(|p| p as usize)
    });

    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|p| p as *mut u8)
    }

    unsafe fn node(base: *mut u8, index: usize) -> *mut RedBlackTreeNode {
        base.add(0x100 + index * core::mem::size_of::<RedBlackTreeNode>()).cast()
    }

    unsafe fn reset(base: *mut u8) {
        ptr::write_bytes(base, 0, 0x1000);
    }

    unsafe fn initialize(
        node: *mut RedBlackTreeNode,
        parent: *mut RedBlackTreeNode,
        left: *mut RedBlackTreeNode,
        right: *mut RedBlackTreeNode,
    ) {
        node.write(RedBlackTreeNode {
            color: 0x5a5a_5a5a,
            parent: parent as usize as u32,
            left: left as usize as u32,
            right: right as usize as u32,
        });
    }

    #[test]
    fn advances_through_right_subtrees_parent_edges_and_sentinel() {
        let Some(base) = try_slab() else {
            crate::testing::note_missing_u32_fixture("red_black_tree_increment");
            return;
        };

        unsafe {
            // Right-subtree case: select the leftmost node in the right subtree.
            reset(base);
            let current = node(base, 0);
            let right = node(base, 1);
            let leftmost = node(base, 2);
            initialize(current, ptr::null_mut(), ptr::null_mut(), right);
            initialize(right, current, leftmost, ptr::null_mut());
            initialize(leftmost, right, ptr::null_mut(), ptr::null_mut());
            let mut cursor = current as usize as u32;
            assert_eq!(red_black_tree_increment(&mut cursor), current as usize as u32);
            assert_eq!(cursor, leftmost as usize as u32);
            assert_eq!((*current).color, 0x5a5a_5a5a);

            // Left-child case: the first parent is the successor.
            reset(base);
            let current = node(base, 0);
            let parent = node(base, 1);
            let sibling = node(base, 2);
            initialize(parent, ptr::null_mut(), current, sibling);
            initialize(current, parent, ptr::null_mut(), ptr::null_mut());
            initialize(sibling, parent, ptr::null_mut(), ptr::null_mut());
            cursor = current as usize as u32;
            assert_eq!(red_black_tree_increment(&mut cursor), current as usize as u32);
            assert_eq!(cursor, parent as usize as u32);

            // Repeated right-child climbs stop at the header sentinel.
            reset(base);
            let header = node(base, 0);
            let root = node(base, 1);
            let ancestor = node(base, 2);
            let maximum = node(base, 3);
            initialize(header, root, ptr::null_mut(), maximum);
            initialize(root, header, ptr::null_mut(), ancestor);
            initialize(ancestor, root, ptr::null_mut(), maximum);
            initialize(maximum, ancestor, ptr::null_mut(), ptr::null_mut());
            cursor = maximum as usize as u32;
            assert_eq!(red_black_tree_increment(&mut cursor), maximum as usize as u32);
            assert_eq!(cursor, header as usize as u32);

            // The sentinel's right-link equality preserves it as the result.
            reset(base);
            let header = node(base, 0);
            let root = node(base, 1);
            initialize(header, root, ptr::null_mut(), root);
            initialize(root, header, ptr::null_mut(), ptr::null_mut());
            cursor = root as usize as u32;
            assert_eq!(red_black_tree_increment(&mut cursor), root as usize as u32);
            assert_eq!(cursor, header as usize as u32);
        }
    }
}
