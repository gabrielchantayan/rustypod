//! Red-black-tree iterator range distance accumulation.
//!
//! Original `FUN_083e7a40` at load address `0x083e7a40`: true size 156
//! bytes, through return at `0x083e7ad8`; next function `0x083e7adc`.
//! Full-image aligned A32 decoding verifies one plain inbound BL at
//! `0x083d71c8`, zero predicated inbound BLs, and no outbound BLs.
//! Adds the in-order distance [first, last) to an existing wrapping counter.
//! Descends right-child left spines or climbs parents with the header sentinel
//! comparison preserved. Neither iterator is modified; last is reloaded each
//! iteration. Raw r0 returns 1, contrary to Ghidra's void signature.
//! Deliberate deviations: none. Byte-identical to the neighboring
//! `0x083e7adc` body; reuses its target-width node layout without callee seams.
//! ARM nm verifies the export; LLVM folds it with `red_black_tree_range_count`.
//! match.py cannot extract the alias label. Comparison via the primary label
//! shows 33 instructions preserving traversal, wrapping increment, end reload,
//! sentinel handling, and return 1 (original: 39 instructions).

use super::red_black_tree_increment::RedBlackTreeNode;

/// # Safety
/// Iterator words and count must be aligned readable memory, count writable.
/// The range must be reachable through valid target-width tree links and its
/// header sentinel. The counter may alias last, which is reloaded each time.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_range_count_083e7a40(
    first: *const u32, last: *const u32, count: *mut u32,
) -> u32 {
    let mut current = first.read() as usize as *const RedBlackTreeNode;
    while current as usize as u32 != last.read() {
        count.write(count.read().wrapping_add(1));
        let mut next = (*current).right as usize as *const RedBlackTreeNode;
        if !next.is_null() {
            current = next;
            while (*current).left != 0 {
                current = (*current).left as usize as *const RedBlackTreeNode;
            }
        } else {
            next = (*current).parent as usize as *const RedBlackTreeNode;
            while (*next).right == current as usize as u32 {
                current = next;
                next = (*next).parent as usize as *const RedBlackTreeNode;
            }
            if (*current).right != next as usize as u32 {
                current = next;
            }
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_range_does_not_dereference_node_or_counter() {
        let cursor = 0u32;
        assert_eq!(unsafe {
            red_black_tree_range_count_083e7a40(&cursor, &cursor, core::ptr::null_mut())
        }, 1);
    }

    #[test]
    fn balanced_tree_ranges_wrap_preserve_iterators_and_reload_aliased_end() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_RANGE_COUNT_083E7A40, 0x1000,
        ).expect("target-width tree fixture");
        let nodes = slab.cast::<RedBlackTreeNode>();
        unsafe {
            let address = |index: usize| nodes.add(index) as usize as u32;
            // Header plus seven nodes in key order: right-subtree left spines,
            // multi-level parent climbs, and the special header termination.
            let links = [(4, 1, 7), (2, 0, 0), (4, 1, 3), (2, 0, 0),
                         (0, 2, 6), (6, 0, 0), (4, 5, 7), (6, 0, 0)];
            for (index, &(parent, left, right)) in links.iter().enumerate() {
                nodes.add(index).write(RedBlackTreeNode {
                    color: 0, parent: address(parent),
                    left: if left == 0 { 0 } else { address(left) },
                    right: if right == 0 { 0 } else { address(right) },
                });
            }
            let order = [1, 2, 3, 4, 5, 6, 7, 0];
            for start in 0..order.len() {
                for end in start..order.len() {
                    let first = address(order[start]);
                    let last = address(order[end]);
                    let mut count = u32::MAX - 2;
                    assert_eq!(red_black_tree_range_count_083e7a40(&first, &last, &mut count), 1);
                    assert_eq!(count, (u32::MAX - 2).wrapping_add((end - start) as u32));
                    assert_eq!(first, address(order[start]));
                    assert_eq!(last, address(order[end]));
                }
            }
            let first = address(7);
            let mut end_count = address(0) - 1;
            let shared = &mut end_count as *mut u32;
            assert_eq!(red_black_tree_range_count_083e7a40(&first, shared, shared), 1);
            assert_eq!(end_count, address(0));
        }
    }
}
