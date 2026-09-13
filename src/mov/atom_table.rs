//! Fourcc-keyed MOV atom-table lookup — original: `FUN_080a3ea0` @
//! **0x080a3ea0** (168 bytes, 0x080a3ea0..0x080a3f48). The next separately
//! linked function starts at 0x080a3f48 with `push {r2, r3, r4, lr}`, so
//! Ghidra's extent is exact. Raw decoding finds **7 direct `bl` call sites**,
//! all unconditional (zero predicated forms): recursive calls at
//! 0x080a3f1c/0x080a3f34 and external callers at 0x081c20c0, 0x081c2194,
//! 0x081c8054, 0x081d8360, and 0x081f3eb4. No aligned data word references
//! the address.
//!
//! # Algorithm
//!
//! Search a node tree by raw fourcc. A matching populated node, or any match
//! when `populate` is nonzero, returns immediately. A matching placeholder
//! (`offset_lo == offset_hi == -1`) follows its duplicate-fourcc chain. The
//! last placeholder grows that chain with `mov_atom_node_new(fourcc)`. A
//! nonmatching node searches child-B before child-A, returning NULL at an
//! absent link. There are no NULL guards beyond the candidate-link test;
//! every non-NULL node is dereferenced as in stock.
//!
//! # Deviations
//!
//! None. Duplicate-chain traversal remains iterative, matching the stock
//! back-edge to 0x080a3ea4; child-B is searched before child-A.

use crate::mov::atom_node::{mov_atom_node_new, MovAtomNode};

#[inline]
fn node_from_word(link: u32) -> *mut MovAtomNode {
    link as usize as *mut MovAtomNode
}

/// Finds a MOV atom-table node by `fourcc`, optionally creating a placeholder.
/// Original: `FUN_080a3ea0` @ **0x080a3ea0** (168 bytes; 7 unconditional
/// direct `bl` call sites, binary-verified).
///
/// `populate == 0` skips matching placeholder nodes until it finds a populated
/// duplicate or appends a new placeholder. Any nonzero `populate` returns the
/// first matching node, including a placeholder.
///
/// # Safety
///
/// Every nonzero node-link word reached from `root` must name a readable
/// [`MovAtomNode`]. When a new placeholder is appended, its terminal node
/// must be writable. This preserves stock's lack of invalid-link guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_atom_table_find")]
pub unsafe extern "C" fn mov_atom_table_find(
    root: *mut MovAtomNode,
    fourcc: u32,
    populate: u32,
) -> *mut MovAtomNode {
    let mut node = root;

    loop {
        if node.is_null() {
            return core::ptr::null_mut();
        }

        let node_fourcc = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).fourcc)) };
        if node_fourcc == fourcc {
            if populate != 0 {
                return node;
            }
            let offset_lo = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).offset_lo)) };
            let offset_hi = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).offset_hi)) };
            if offset_lo != u32::MAX || offset_hi != u32::MAX {
                return node;
            }

            let duplicate = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).dup_chain)) };
            if duplicate != 0 {
                node = node_from_word(duplicate);
                continue;
            }

            let created = unsafe { mov_atom_node_new(fourcc) };
            if !created.is_null() {
                unsafe {
                    core::ptr::write_volatile(
                        core::ptr::addr_of_mut!((*node).dup_chain),
                        created as usize as u32,
                    );
                }
            }
            return created;
        }

        let child_b = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).child_b)) };
        let found = unsafe { mov_atom_table_find(node_from_word(child_b), fourcc, populate) };
        if !found.is_null() {
            return found;
        }

        let child_a = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).child_a)) };
        node = node_from_word(child_a);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex as TestMutex};

    const NODE_COUNT: usize = 8;
    const NODE_BYTES: usize = NODE_COUNT * core::mem::size_of::<MovAtomNode>();
    static NODE_SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::MOV_ATOM_TABLE_LOOKUP, NODE_BYTES).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: TestMutex<()> = TestMutex::new(());

    fn nodes() -> Option<*mut MovAtomNode> {
        (*NODE_SLAB).map(|address| address as *mut MovAtomNode)
    }

    unsafe fn node_at(nodes: *mut MovAtomNode, index: usize) -> *mut MovAtomNode {
        unsafe { nodes.add(index) }
    }

    unsafe fn reset_nodes(nodes: *mut MovAtomNode) {
        unsafe { core::ptr::write_bytes(nodes.cast::<u8>(), 0, NODE_BYTES) };
    }

    unsafe fn set_node(node: *mut MovAtomNode, fourcc: u32, placeholder: bool) {
        unsafe {
            core::ptr::write(
                node,
                MovAtomNode {
                    child_a: 0,
                    child_b: 0,
                    dup_chain: 0,
                    unused_0c: 0,
                    offset_lo: if placeholder { u32::MAX } else { 0 },
                    offset_hi: if placeholder { u32::MAX } else { 0 },
                    size_lo: u32::MAX,
                    size_hi: u32::MAX,
                    flag: 0,
                    kind: 0,
                    pad_22: [0; 2],
                    fourcc,
                },
            );
        }
    }

    fn node_word(node: *mut MovAtomNode) -> u32 {
        node as usize as u32
    }

    #[test]
    fn returns_null_for_an_absent_root() {
        assert!(unsafe { mov_atom_table_find(core::ptr::null_mut(), 0x6468_6b74, 0) }.is_null());
    }

    #[test]
    fn returns_matching_populated_or_requested_placeholder_node() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(nodes) = nodes() else {
            assert!(note_missing_u32_fixture("mov/atom_table"));
            return;
        };
        unsafe {
            reset_nodes(nodes);
            let root = node_at(nodes, 0);
            set_node(root, u32::from_le_bytes(*b"tkhd"), false);
            assert_eq!(mov_atom_table_find(root, u32::from_le_bytes(*b"tkhd"), 0), root);

            set_node(root, u32::from_le_bytes(*b"tkhd"), true);
            assert_eq!(mov_atom_table_find(root, u32::from_le_bytes(*b"tkhd"), 1), root);
            assert_eq!((*root).dup_chain, 0, "populate returns rather than appending");
        }
    }

    #[test]
    fn follows_duplicate_chain_before_creating_a_placeholder() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(nodes) = nodes() else {
            assert!(note_missing_u32_fixture("mov/atom_table"));
            return;
        };
        unsafe {
            reset_nodes(nodes);
            let root = node_at(nodes, 0);
            let populated_duplicate = node_at(nodes, 1);
            let fourcc = u32::from_le_bytes(*b"stsd");
            set_node(root, fourcc, true);
            set_node(populated_duplicate, fourcc, false);
            (*root).dup_chain = node_word(populated_duplicate);

            assert_eq!(mov_atom_table_find(root, fourcc, 0), populated_duplicate);
            assert_eq!((*root).dup_chain, node_word(populated_duplicate));
        }
    }

    #[test]
    fn searches_child_b_before_child_a_then_falls_back_to_child_a() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(nodes) = nodes() else {
            assert!(note_missing_u32_fixture("mov/atom_table"));
            return;
        };
        unsafe {
            reset_nodes(nodes);
            let root = node_at(nodes, 0);
            let child_b = node_at(nodes, 1);
            let child_a = node_at(nodes, 2);
            let target = u32::from_le_bytes(*b"moov");
            set_node(root, u32::from_le_bytes(*b"root"), false);
            set_node(child_b, target, false);
            set_node(child_a, target, false);
            (*root).child_b = node_word(child_b);
            (*root).child_a = node_word(child_a);

            assert_eq!(mov_atom_table_find(root, target, 0), child_b);
            (*child_b).fourcc = u32::from_le_bytes(*b"skip");
            assert_eq!(mov_atom_table_find(root, target, 0), child_a);
        }
    }

    #[test]
    fn appends_a_new_placeholder_at_the_terminal_duplicate_link() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(nodes) = nodes() else {
            assert!(note_missing_u32_fixture("mov/atom_table"));
            return;
        };
        let _heap = mock_heap();
        unsafe {
            reset_nodes(nodes);
            let root = node_at(nodes, 0);
            let allocated = node_at(nodes, 7);
            let fourcc = u32::from_le_bytes(*b"trak");
            set_node(root, fourcc, true);
            set_alloc_ret(allocated.cast());

            let created = mov_atom_table_find(root, fourcc, 0);

            assert_eq!(created, allocated);
            assert_eq!(alloc_log(), (1, core::mem::size_of::<MovAtomNode>(), 2));
            assert_eq!((*root).dup_chain, node_word(allocated));
            assert_eq!((*allocated).fourcc, fourcc);
            assert_eq!(((*allocated).offset_lo, (*allocated).offset_hi), (u32::MAX, u32::MAX));
        }
    }
}
