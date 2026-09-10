//! Tree flag-bit propagation — `FUN_08157ea0` @ `0x08157ea0` (120 bytes).
//!
//! ## Verified call sites
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds 11 direct
//! `bl` callers: ten unconditional plus `blne` at `0x081412c8`. The recursive
//! call at `0x08157ee8` is one of the ten. A separate `bne` tail transfer at
//! `0x081412f4` reaches this entry; no image word contains its address.
//!
//! ## Algorithm
//!
//! First applies `mode` to bit 3 (`0x08`) of `node->flags` at `+0x48`. It then
//! walks the collection at `+0xa8`. Each child is queried through vtable slot
//! `+0x14` with `0x1100`: a zero result applies the bit to that child, while
//! any nonzero result recursively walks that child. The collection cursor is
//! always invalidated after its final refusing advance. Neither `node` nor a
//! yielded null child is guarded before the flag store, matching retailOS.
//!
//! ## Deliberate deviations
//!
//! The stock body calls the unported 40-byte helper `0x0826d80c` for each
//! flag update. Its raw instructions are only the compare-and-store of this
//! same bit, so that exact operation is kept private here rather than adding
//! a second exported port or a dispatch seam for an already fully recovered
//! leaf helper.

use crate::util::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};

/// Mask of the propagated word flag.
pub const TREE_FLAG_BIT_3: u32 = 0x08;
/// Selector passed to every child vtable query.
pub const CHILD_WALK_MODE_QUERY: u32 = 0x1100;

/// Tree-node vtable fields reached by [`propagate_tree_flag_bit_3`].
#[repr(C)]
pub struct TreeNodeVtable {
    /// Slots `+0x00..+0x10`, not inspected by this port.
    pub unresolved: [usize; 5],
    /// Slot `+0x14`: returns nonzero when the child owns a descendant walk.
    pub child_walk_mode_query: unsafe extern "C" fn(node: *mut TreeNode, mode: u32) -> u32,
}

/// Recovered prefix and child collection of the tree node.
#[repr(C)]
pub struct TreeNode {
    /// `+0x00`: virtual-method table.
    pub vtable: *const TreeNodeVtable,
    /// `+0x04..+0x44`: fields not touched here.
    pub _reserved_04_44: [u32; 17],
    /// `+0x48`: includes [`TREE_FLAG_BIT_3`].
    pub flags: u32,
    /// `+0x4c..+0xa4`: fields not touched here.
    pub _reserved_4c_a4: [u32; 23],
    /// `+0xa8`: children walked through the shared collection cursor.
    pub children: Collection,
}

#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x14] = [0; core::mem::offset_of!(TreeNodeVtable, child_walk_mode_query)];
    const _: [u8; 0x48] = [0; core::mem::offset_of!(TreeNode, flags)];
    const _: [u8; 0xa8] = [0; core::mem::offset_of!(TreeNode, children)];
}

/// Reproduces the unported helper `0x0826d80c` used by this one caller.
#[inline(always)]
unsafe fn set_tree_node_flag_bit_3(node: *mut TreeNode, mode: u32) {
    let flags = (*node).flags;
    if ((flags & TREE_FLAG_BIT_3) >> 3) == mode {
        return;
    }
    (*node).flags = if mode == 0 {
        flags & !TREE_FLAG_BIT_3
    } else {
        flags | TREE_FLAG_BIT_3
    };
}

/// propagate_tree_flag_bit_3 — original: `FUN_08157ea0` @ `0x08157ea0`
/// (120 bytes).
///
/// Applies `mode` to this node and each non-recursive child. A child whose
/// `+0x14` query returns nonzero is processed recursively instead.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn propagate_tree_flag_bit_3(node: *mut TreeNode, mode: u32) {
    set_tree_node_flag_bit_3(node, mode);

    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, &mut (*node).children);
    let mut child: *mut TreeNode = core::ptr::null_mut();
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(child).cast()) != 0 {
        let recurse = if child.is_null() {
            0
        } else {
            ((*(*child).vtable).child_walk_mode_query)(child, CHILD_WALK_MODE_QUERY)
        };
        if recurse == 0 {
            set_tree_node_flag_bit_3(child, mode);
        } else {
            propagate_tree_flag_bit_3(child, mode);
        }
    }
    cursor_invalidate(&mut cursor);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    #[repr(C)]
    struct TestCollection {
        vtable: *const crate::util::cursor::CollectionVtable,
        items: Vec<*mut TreeNode>,
        seen_indices: Vec<i32>,
    }

    #[repr(C)]
    struct TestNode {
        vtable: *const TreeNodeVtable,
        reserved_04_44: [u32; 17],
        flags: u32,
        reserved_4c_a4: [u32; 23],
        children: TestCollection,
        recursive: u32,
        query_modes: Vec<u32>,
    }

    unsafe extern "C" fn child_at(
        collection: *mut Collection,
        index: i32,
        out: *mut u8,
    ) -> u32 {
        let collection = collection.cast::<TestCollection>();
        (*collection).seen_indices.push(index);
        if index < 0 || index as usize >= (*collection).items.len() {
            return 0;
        }
        let item = (&(*collection).items)[index as usize];
        out.cast::<*mut TreeNode>().write(item);
        1
    }

    unsafe extern "C" fn child_walk_mode_query(node: *mut TreeNode, mode: u32) -> u32 {
        let node = node.cast::<TestNode>();
        (*node).query_modes.push(mode);
        (*node).recursive
    }

    static COLLECTION_VTABLE: crate::util::cursor::CollectionVtable =
        crate::util::cursor::CollectionVtable { unresolved: [0; 15], item_at: child_at };
    static TREE_NODE_VTABLE: TreeNodeVtable = TreeNodeVtable {
        unresolved: [0; 5],
        child_walk_mode_query,
    };

    impl TestNode {
        fn new(flags: u32, recursive: u32) -> Self {
            Self {
                vtable: &TREE_NODE_VTABLE,
                reserved_04_44: [0; 17],
                flags,
                reserved_4c_a4: [0; 23],
                children: TestCollection {
                    vtable: &COLLECTION_VTABLE,
                    items: Vec::new(),
                    seen_indices: Vec::new(),
                },
                recursive,
                query_modes: Vec::new(),
            }
        }

        fn as_tree_node(&mut self) -> *mut TreeNode {
            (self as *mut Self).cast()
        }
    }

    #[test]
    fn nonzero_mode_sets_the_bit_across_nested_and_leaf_children() {
        let mut grandchild = TestNode::new(0x20, 0);
        let mut branch = TestNode::new(0x40, 2);
        branch.children.items.push(grandchild.as_tree_node());
        let mut leaf = TestNode::new(0x80, 0);
        let mut root = TestNode::new(0x100, 0);
        root.children.items.push(branch.as_tree_node());
        root.children.items.push(leaf.as_tree_node());

        unsafe { propagate_tree_flag_bit_3(root.as_tree_node(), 7) };

        assert_eq!(root.flags, 0x108);
        assert_eq!(branch.flags, 0x48);
        assert_eq!(grandchild.flags, 0x28);
        assert_eq!(leaf.flags, 0x88);
        assert_eq!(branch.query_modes, Vec::from([CHILD_WALK_MODE_QUERY]));
        assert_eq!(grandchild.query_modes, Vec::from([CHILD_WALK_MODE_QUERY]));
        assert_eq!(leaf.query_modes, Vec::from([CHILD_WALK_MODE_QUERY]));
        assert_eq!(root.children.seen_indices, Vec::from([0, 1, 2]));
        assert_eq!(branch.children.seen_indices, Vec::from([0, 1]));
    }

    #[test]
    fn zero_mode_clears_the_bit_across_recursive_children() {
        let mut grandchild = TestNode::new(0x38, 0);
        let mut branch = TestNode::new(0x28, 1);
        branch.children.items.push(grandchild.as_tree_node());
        let mut leaf = TestNode::new(0x18, 0);
        let mut root = TestNode::new(0x08, 0);
        root.children.items.push(branch.as_tree_node());
        root.children.items.push(leaf.as_tree_node());

        unsafe { propagate_tree_flag_bit_3(root.as_tree_node(), 0) };

        assert_eq!(root.flags, 0);
        assert_eq!(branch.flags, 0x20);
        assert_eq!(grandchild.flags, 0x30);
        assert_eq!(leaf.flags, 0x10);
    }

    #[test]
    fn empty_children_still_update_the_root_and_refuse_index_zero() {
        let mut root = TestNode::new(0x20, 0);

        unsafe { propagate_tree_flag_bit_3(root.as_tree_node(), 1) };

        assert_eq!(root.flags, 0x28);
        assert_eq!(root.children.seen_indices, Vec::from([0]));
        assert!(root.query_modes.is_empty());
    }
}
