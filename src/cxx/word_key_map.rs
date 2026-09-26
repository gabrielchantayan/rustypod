//! Find on a word-keyed `_Rb_tree` map — libstdc++'s
//! `_Rb_tree<unsigned, pair<const unsigned, V>>::_M_find` for the map
//! instantiation whose nodes carry a u32 key plus a u32 mapped word.
//!
//! - [`word_key_map_find`] — originals: `FUN_083dbb5c` @ 0x083dbb5c
//!   (168 bytes; 4 verified direct `bl` call sites, all unconditional:
//!   0x081f09a0, 0x081f0ad0, 0x081f0bdc, 0x081f0f84) and
//!   `FUN_083dbc64` @ 0x083dbc64 (168 bytes; 2 verified direct `bl` call
//!   sites, both unconditional: 0x081e1504 and 0x081e1554).
//!
//! Container and node shape (same family as `cxx/word_key_set.rs` and
//! `cxx/byte_key_map.rs`): the header node pointer lives at map+0x10
//! (header+4 = root), the comparator object at map+0x19. Nodes are the
//! 0x10-byte `_Rb_tree_node_base` header (color byte, parent, left +8,
//! right +0xc) followed by the u32 key at +0x10 and the mapped word at
//! +0x14 — the caller at 0x081f09a0 reads the found node's +0x14 and
//! passes it as an argument to a virtual call, i.e. this is
//! `std::map<unsigned, T *>::find`.
//!
//! Algorithm (from the disassembly; the function carries 4 `bl`s,
//! verified against the raw words): classic `find` descent — walk from
//! the root, going right (+0xc) while `node_key < *key` (comparator
//! `less_unsigned` @ 0x083d7598), else remembering the node as the
//! candidate and going left (+8). When the walk falls off the tree the
//! candidate is the lower bound; it is the answer unless it is the
//! header (iterator-equality `equal_deref` @ 0x083cf968) or
//! `*key < candidate_key` (a second `less_unsigned`), in which case the
//! header — `end()` — is the answer. The result node pointer is written
//! through the sret-style out pointer in r0. The key accessor @
//! 0x083b6b3c (`add r0, r0, #16; bx lr`) supplies node+0x10 for the
//! second compare.
//!
//! Deviations:
//! - `less_unsigned` @ 0x083d7598 is already ported and exported
//!   (`cxx/templates.rs`); this port reaches it by real calls,
//!   preserving the original's two `bl` boundaries. The key accessor
//!   @ 0x083b6b3c (`node + 0x10`) and the one-word iterator equality
//!   @ 0x083cf968 are few-instruction leaves and are inlined (the
//!   `byte_key_map` precedent).
//! - The original parks the candidate and header pointers in stack
//!   slots and reloads the chosen slot's pointee for the final store;
//!   the port keeps them in registers. The `str r8, [sp]` zero-store
//!   per descent step is dead scratch (the comparator ignores its
//!   `this`), dropped.

use crate::cxx::templates::less_unsigned;

/// A red-black tree node of this map instantiation: the 0x10-byte
/// `_Rb_tree_node_base` header, the u32 key at +0x10 and the mapped
/// word at +0x14. Fields are typed struct members, never literal byte
/// offsets: the 32-bit target layout is exact (asserted below) while a
/// 64-bit host keeps the fields disjoint (the `WordKeySetNode`
/// precedent in `cxx/word_key_set.rs`).
#[repr(C)]
pub struct WordKeyMapNode {
    /// +0: red-black color byte (0 = red).
    pub color: u8,
    /// +1..+4: padding.
    pub _pad: [u8; 3],
    /// +4: parent link (on the header node: the root).
    pub parent: *mut WordKeyMapNode,
    /// +8: left child (smaller keys), null when absent.
    pub left: *mut WordKeyMapNode,
    /// +0xc: right child, null when absent.
    pub right: *mut WordKeyMapNode,
    /// +0x10: the key.
    pub key: u32,
    /// +0x14: the mapped word. Not read by the find; present so the
    /// target node stride (0x18) is explicit.
    pub value: u32,
}

/// The container as the find reads it: the header node pointer at
/// +0x10 and the stateless comparator object at +0x19 (never read by
/// the comparator; only its address is forwarded). The first 0x10
/// bytes are the node pool, opaque here.
#[repr(C)]
pub struct WordKeyMap {
    /// +0..+0x10: node pool, opaque to the find.
    pub _pool: [u32; 4],
    /// +0x10: header node pointer; header.parent is the root.
    pub header: *mut WordKeyMapNode,
    /// +0x14: live-node count, not read by the find.
    pub node_count: u32,
    /// +0x18: multi-insert flag byte, not read by the find.
    pub multi_insert: u8,
    /// +0x19: the comparator object (`std::less<unsigned>`, stateless).
    pub comparator: u8,
}

// Target-exact layout; on a 64-bit host the pointer fields widen and
// the offsets shift — harmless, all access goes through the structs.
#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _KEY_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(WordKeyMapNode, key)];
    const _VALUE_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(WordKeyMapNode, value)];
    const _NODE_SIZE: [u8; 0x18] = [0; core::mem::size_of::<WordKeyMapNode>()];
    const _HEADER_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(WordKeyMap, header)];
    const _COMPARATOR_OFFSET: [u8; 0x19] = [0; core::mem::offset_of!(WordKeyMap, comparator)];
}

/// word_key_map_find — originals: `FUN_083dbb5c` @ 0x083dbb5c and
/// `FUN_083dbc64` @ 0x083dbc64 (168 bytes each; 4 and 2 inbound plain `bl`
/// call sites respectively; no predicated `bl` forms). Raw A32 establishes
/// the latter's extent through `pop {r0-r10,pc}` at 0x083dbd08; the new
/// separately entered function begins at 0x083dbd0c.
///
/// Writes the node for `*key` — or the header node (`end()`) when the
/// key is absent — through `out`. Lower-bound descent from the root
/// comparing u32 keys with `less_unsigned`; the candidate is rejected
/// when it is the header or when `*key < candidate_key`. The two retail
/// copies differ only in their byte-identical key-accessor and iterator-
/// equality helper addresses, so this established implementation ports both.
/// Deliberate deviations: the retail stack homes and dead zero scratch store
/// are held in registers; helper leaves are inlined except for the two real
/// comparator call boundaries.
///
/// # Safety
/// `out` must point at a writable word, `map` at a live container
/// matching the scouted [`WordKeyMap`] layout, and `key` at a readable
/// aligned u32. The tree links must be well-formed (null-terminated).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_key_map_find(
    out: *mut *mut WordKeyMapNode,
    map: *mut WordKeyMap,
    key: *const u32,
) {
    let header = (*map).header;
    let comparator = &(*map).comparator as *const u8;
    let mut candidate = header;
    let mut node = (*header).parent;
    while !node.is_null() {
        if less_unsigned(comparator, &(*node).key, key) != 0 {
            node = (*node).right;
        } else {
            candidate = node;
            node = (*node).left;
        }
    }
    if candidate == header || less_unsigned(comparator, key, &(*candidate).key) != 0 {
        candidate = header;
    }
    out.write(candidate);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::boxed::Box;
    use std::vec::Vec;

    fn node(key: u32) -> WordKeyMapNode {
        WordKeyMapNode {
            color: 1,
            _pad: [0; 3],
            parent: ptr::null_mut(),
            left: ptr::null_mut(),
            right: ptr::null_mut(),
            key,
            value: key.wrapping_mul(7),
        }
    }

    struct Tree {
        map: Box<WordKeyMap>,
        header: Box<WordKeyMapNode>,
        nodes: Vec<Box<WordKeyMapNode>>,
    }

    /// Builds a tree from `(key, left, right)` rows indexed by position:
    /// row 0 is the root, `usize::MAX` marks a null child.
    fn tree(rows: &[(u32, usize, usize)]) -> Tree {
        let mut header = Box::new(node(0));
        let mut nodes: Vec<Box<WordKeyMapNode>> =
            rows.iter().map(|&(key, _, _)| Box::new(node(key))).collect();
        for (i, &(_, left, right)) in rows.iter().enumerate() {
            if left != usize::MAX {
                nodes[i].left = &mut *nodes[left];
                nodes[left].parent = &mut *nodes[i];
            }
            if right != usize::MAX {
                nodes[i].right = &mut *nodes[right];
                nodes[right].parent = &mut *nodes[i];
            }
        }
        header.parent = if rows.is_empty() {
            ptr::null_mut()
        } else {
            &mut *nodes[0]
        };
        let mut map = Box::new(WordKeyMap {
            _pool: [0; 4],
            header: ptr::null_mut(),
            node_count: rows.len() as u32,
            multi_insert: 0,
            comparator: 0,
        });
        map.header = &mut *header;
        Tree { map, header, nodes }
    }

    fn find(t: &mut Tree, key: u32) -> *mut WordKeyMapNode {
        let mut out: *mut WordKeyMapNode = ptr::null_mut();
        unsafe { word_key_map_find(&mut out, &mut *t.map, &key) };
        out
    }

    /// Balanced three-node tree: keys 10 (root), 5 (left), 20 (right).
    fn three() -> Tree {
        tree(&[(10, 1, 2), (5, usize::MAX, usize::MAX), (20, usize::MAX, usize::MAX)])
    }

    #[test]
    fn empty_tree_returns_the_header() {
        let mut t = tree(&[]);
        let header = &mut *t.header as *mut _;
        assert_eq!(find(&mut t, 42), header);
    }

    #[test]
    fn finds_every_present_key() {
        let mut t = three();
        let header = &mut *t.header as *mut _;
        for i in 0..3 {
            let want = &mut *t.nodes[i] as *mut _;
            let key = t.nodes[i].key;
            assert_eq!(find(&mut t, key), want);
            assert_ne!(want, header);
        }
    }

    #[test]
    fn absent_keys_return_the_header() {
        let mut t = three();
        let header = &mut *t.header as *mut _;
        // Below every key, between the keys, above every key.
        for key in [0, 7, 15, 100, u32::MAX] {
            assert_eq!(find(&mut t, key), header, "key {key}");
        }
    }

    #[test]
    fn descent_reaches_deeper_nodes() {
        // Right-leaning chain 10 -> 20 -> 30 plus a left leaf 5.
        let mut t = tree(&[
            (10, 3, 1),
            (20, usize::MAX, 2),
            (30, usize::MAX, usize::MAX),
            (5, usize::MAX, usize::MAX),
        ]);
        let want = &mut *t.nodes[2] as *mut _;
        assert_eq!(find(&mut t, 30), want);
        let want = &mut *t.nodes[3] as *mut _;
        assert_eq!(find(&mut t, 5), want);
        let header = &mut *t.header as *mut _;
        assert_eq!(find(&mut t, 25), header);
    }

    #[test]
    fn unsigned_ordering_governs_the_walk() {
        // u32::MAX as a key must sort above 1, not below it.
        let mut t = tree(&[(1, usize::MAX, 1), (u32::MAX, usize::MAX, usize::MAX)]);
        let want = &mut *t.nodes[1] as *mut _;
        assert_eq!(find(&mut t, u32::MAX), want);
        let header = &mut *t.header as *mut _;
        assert_eq!(find(&mut t, u32::MAX - 1), header);
    }

    #[test]
    fn second_retail_copy_contract_finds_and_rejects_boundary_keys() {
        // FUN_083dbc64 is the second physical instantiation of this exact
        // target-width map layout; exercise its caller-visible contract at
        // both unsigned ordering boundaries.
        let mut t = tree(&[(1, usize::MAX, 1), (u32::MAX, usize::MAX, usize::MAX)]);
        let max = &mut *t.nodes[1] as *mut _;
        assert_eq!(find(&mut t, u32::MAX), max);
        let header = &mut *t.header as *mut _;
        assert_eq!(find(&mut t, 0), header);
        assert_eq!(find(&mut t, u32::MAX - 1), header);
    }
}
