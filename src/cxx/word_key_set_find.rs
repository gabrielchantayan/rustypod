//! `word_key_set_find` — retailOS `FUN_083c023c` @ `0x083c023c`.
//! True extent: 156 bytes, `0x083c023c..0x083c02d8` (next function's push).
//! Raw aligned A32 decoding verifies one inbound plain BL at 0x08257da0,
//! zero predicated inbound BLs; three outbound plain BLs at 0x083c026c,
//! 0x083c02a0 and 0x083c02b0, zero predicated outbound BLs.
//!
//! Walks the unsigned-word tree's lower bound, retaining the latest node
//! not less than the query, then checks query < candidate to reject a miss.
//! Writes the first equal node, or the header sentinel, to the output iterator.
//! Deliberate deviations: typed fields widen safely on hosts; node-key accessor
//! @ 0x083b6a2c is folded into field addressing. Dead stack spills and restored
//! scratch-register values (Ghidra's spurious u64 return) are omitted.

use super::templates::less_unsigned_alias_74c4;
use super::word_key_set::{WordKeySet, WordKeySetNode};

/// All pointers must be valid and aligned; links must form a valid ordered tree.
/// The header need not contain an initialized key. Output may alias the query.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_key_set_find(
    out: *mut *mut WordKeySetNode,
    tree: *const WordKeySet,
    key: *const u32,
) {
    let header = (*tree).header;
    let comparator = core::ptr::addr_of!((*tree).comparator);
    let mut candidate = header;
    let mut node = (*header).parent;
    while !node.is_null() {
        if less_unsigned_alias_74c4(comparator, core::ptr::addr_of!((*node).key), key) == 0 {
            candidate = node;
            node = (*node).left;
        } else {
            node = (*node).right;
        }
    }
    if candidate != header
        && less_unsigned_alias_74c4(comparator, key, core::ptr::addr_of!((*candidate).key)) != 0
    {
        candidate = header;
    }
    out.write(candidate);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;

    fn node(key: u32) -> Box<WordKeySetNode> {
        Box::new(WordKeySetNode {
            color: 0, _pad: [0; 3], parent: core::ptr::null_mut(),
            left: core::ptr::null_mut(), right: core::ptr::null_mut(), key,
        })
    }

    #[test]
    fn finds_first_equal_unsigned_key_and_rejects_gaps_without_mutation() {
        let keys = [0, 3, 3, 7, 0x7fff_ffff, 0x8000_0000, u32::MAX];
        let mut nodes: Vec<_> = keys.iter().map(|&key| node(key)).collect();
        let mut pointers: Vec<*mut WordKeySetNode> = nodes.iter_mut().map(|n| &mut **n as *mut _).collect();
        // Balanced shape with equal keys on either side of the duplicate root.
        unsafe {
            (*pointers[3]).left = pointers[1];
            (*pointers[3]).right = pointers[5];
            (*pointers[1]).left = pointers[0];
            (*pointers[1]).right = pointers[2];
            (*pointers[5]).left = pointers[4];
            (*pointers[5]).right = pointers[6];
        }
        let before: Vec<_> = nodes.iter().map(|n| (n.parent, n.left, n.right, n.key)).collect();
        let mut header = node(0xdead_beef);
        header.parent = pointers[3];
        let header_ptr = &mut *header as *mut _;
        let mut tree = WordKeySet {
            _opaque: [0; core::mem::size_of::<super::super::word_key_set::WordKeySetNodePool>()],
            header: header_ptr, node_count: keys.len() as u32, multi_insert: 1, comparator: 0,
        };
        for query in [0, 1, 2, 3, 4, 6, 7, 8, 0x7fff_fffe, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, u32::MAX] {
            let expected = keys.iter().position(|&k| k == query).map_or(header_ptr, |i| pointers[i]);
            let mut found = core::ptr::null_mut();
            unsafe { word_key_set_find(&mut found, &tree, &query); }
            assert_eq!(found, expected, "query {query:#x}");
        }
        assert_eq!(before, nodes.iter().map(|n| (n.parent, n.left, n.right, n.key)).collect::<Vec<_>>());
        // An empty tree must not dereference the query at all.
        header.parent = core::ptr::null_mut();
        tree.node_count = 0;
        let mut found = core::ptr::null_mut();
        unsafe { word_key_set_find(&mut found, &tree, core::ptr::null()); }
        assert_eq!(found, header_ptr);
    }
}
