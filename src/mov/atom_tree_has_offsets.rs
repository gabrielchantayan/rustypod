//! `mov_atom_tree_has_offsets` — original: `FUN_081f3aa0` @ **0x081f3aa0**
//! (**144 bytes**, 0x081f3aa0..0x081f3b30, 36 instructions, no literal
//! pool). The next real function opens at 0x081f3b30 (`ldrb r1,[r0]`). Raw
//! decoding finds **7 direct plain `bl` instructions** (four distinct
//! targets, including three recursive calls) and zero predicated `bl` forms.
//!
//! Recursively validates a MOV atom node's child-A (+0x00), child-B (+0x04),
//! and duplicate-fourcc (+0x08) links. A NULL node is valid; every non-NULL
//! node must have a payload offset at +0x10 other than `u64::MAX`, and all
//! three descendants must be valid. The opaque parser argument is only passed
//! to recursive calls and otherwise unread.
//!
//! # Deliberate deviations
//!
//! Rust accesses the three known link words directly rather than adding seams
//! for the stock one-word getters at 0x0814d284/0x0814d2a0/0x0814d2a8. This
//! preserves their observed loads while avoiding unported callee identities.

use crate::mov::atom_node::{mov_atom_node_get_offset, MovAtomNode};

#[inline]
fn node_from_word(link: u32) -> *const MovAtomNode {
    link as usize as *const MovAtomNode
}

/// Validates that `node` and every descendant have a parsed payload offset.
///
/// # Safety
///
/// Every nonzero target-width link reachable from `node` must name a readable
/// [`MovAtomNode`]. Cyclic links recurse forever, as in stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_atom_tree_has_offsets")]
pub unsafe extern "C" fn mov_atom_tree_has_offsets(
    parser: *mut u8,
    node: *const MovAtomNode,
) -> u32 {
    if node.is_null() {
        return 1;
    }
    if unsafe { mov_atom_node_get_offset(node) } == u64::MAX {
        return 0;
    }

    let child_a = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).child_a)) };
    if unsafe { mov_atom_tree_has_offsets(parser, node_from_word(child_a)) } == 0 {
        return 0;
    }
    let child_b = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).child_b)) };
    if unsafe { mov_atom_tree_has_offsets(parser, node_from_word(child_b)) } == 0 {
        return 0;
    }
    let dup_chain = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).dup_chain)) };
    unsafe { mov_atom_tree_has_offsets(parser, node_from_word(dup_chain)) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const NODE_COUNT: usize = 4;
    const NODE_BYTES: usize = NODE_COUNT * core::mem::size_of::<MovAtomNode>();
    static NODE_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MOV_ATOM_TREE_HAS_OFFSETS, NODE_BYTES).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn nodes() -> Option<*mut MovAtomNode> {
        (*NODE_SLAB).map(|address| address as *mut MovAtomNode)
    }

    unsafe fn node_at(nodes: *mut MovAtomNode, index: usize) -> *mut MovAtomNode {
        unsafe { nodes.add(index) }
    }

    unsafe fn node_word(node: *mut MovAtomNode) -> u32 {
        node as usize as u32
    }

    unsafe fn initialize(nodes: *mut MovAtomNode) {
        unsafe { core::ptr::write_bytes(nodes.cast::<u8>(), 0, NODE_BYTES) };
        for index in 0..NODE_COUNT {
            let node = unsafe { node_at(nodes, index) };
            unsafe {
                (*node).offset_lo = index as u32;
                (*node).offset_hi = 0;
            }
        }
    }

    #[test]
    fn accepts_null_and_a_complete_three_link_tree() {
        assert_eq!(unsafe { mov_atom_tree_has_offsets(core::ptr::null_mut(), core::ptr::null()) }, 1);
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(nodes) = nodes() else {
            assert!(note_missing_u32_fixture("mov/atom_tree_has_offsets"));
            return;
        };
        unsafe {
            initialize(nodes);
            let root = node_at(nodes, 0);
            (*root).child_a = node_word(node_at(nodes, 1));
            (*root).child_b = node_word(node_at(nodes, 2));
            (*root).dup_chain = node_word(node_at(nodes, 3));
            assert_eq!(mov_atom_tree_has_offsets(0x1234usize as *mut u8, root), 1);
        }
    }

    #[test]
    fn rejects_an_unparsed_node_on_each_recursive_link() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(nodes) = nodes() else {
            assert!(note_missing_u32_fixture("mov/atom_tree_has_offsets"));
            return;
        };
        unsafe {
            for link in 0..3 {
                initialize(nodes);
                let root = node_at(nodes, 0);
                let child = node_at(nodes, 1);
                (*root).offset_lo = 0x10;
                (*child).offset_lo = u32::MAX;
                (*child).offset_hi = u32::MAX;
                match link {
                    0 => (*root).child_a = node_word(child),
                    1 => (*root).child_b = node_word(child),
                    _ => (*root).dup_chain = node_word(child),
                }
                assert_eq!(mov_atom_tree_has_offsets(core::ptr::null_mut(), root), 0);
            }
        }
    }
}
