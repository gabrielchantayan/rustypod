//! Red-black-tree iterator range distance accumulation.
//!
//! Original `FUN_083e7cb0` at load address `0x083e7cb0`: true size 156
//! bytes, through the return at `0x083e7d48`; next function `0x083e7d4c`.
//! Full-image raw A32 decoding verifies one plain inbound BL (0x081854b4),
//! zero predicated inbound BLs, and zero outbound BLs of either kind.
//! Adds one to an existing wrapping counter for each node in [first, last).
//! Successors descend the right subtree's left spine or climb parent links,
//! retaining the header-sentinel right-link comparison. Neither input cursor
//! is changed; last is reloaded on each comparison. Returns 1, as raw r0 does
//! on exit (Ghidra incorrectly reports void). The caller's r3 is unused.
//! Deliberate deviations: none. Reuses the established target-width node
//! layout and keeps the successor walk inline, matching the call-free body.

use super::red_black_tree_increment::RedBlackTreeNode;

/// # Safety
/// The iterator words and counter must be valid aligned readable memory,
/// with count writable. The range must be reachable through valid tree links
/// and its header sentinel. Node links contain target-width addresses.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_range_count(
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
    fn empty_range_does_not_dereference_nodes_or_change_count() {
        let cursor = 0u32;
        let mut count = 0x12345678;
        assert_eq!(unsafe { red_black_tree_range_count(&cursor, &cursor, &mut count) }, 1);
        assert_eq!(count, 0x12345678);
    }

    #[test]
    fn all_subranges_preserve_iterators_and_wrap_existing_count() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_RANGE_COUNT, 0x1000,
        ).expect("target-width tree fixture");
        let nodes = slab.cast::<RedBlackTreeNode>();
        unsafe {
            let address = |index: usize| nodes.add(index) as usize as u32;
            // Balanced seven-node tree. Slot zero is the circular header.
            // In-order sequence is 1,2,3,4,5,6,7,header.
            let links = [
                (4, 1, 7), (2, 0, 0), (4, 1, 3), (2, 0, 0),
                (0, 2, 6), (6, 0, 0), (4, 5, 7), (6, 0, 0),
            ];
            for (index, &(parent, left, right)) in links.iter().enumerate() {
                nodes.add(index).write(RedBlackTreeNode {
                    color: 0,
                    parent: address(parent),
                    left: if left == 0 { 0 } else { address(left) },
                    right: if right == 0 { 0 } else { address(right) },
                });
            }
            let order = [1, 2, 3, 4, 5, 6, 7, 0];
            for start in 0..order.len() {
                for end in start..order.len() {
                    for initial in [0u32, 17, u32::MAX - 2, u32::MAX] {
                        let first = address(order[start]);
                        let last = address(order[end]);
                        let mut count = initial;
                        assert_eq!(red_black_tree_range_count(&first, &last, &mut count), 1);
                        assert_eq!(count, initial.wrapping_add((end - start) as u32));
                        assert_eq!(first, address(order[start]));
                        assert_eq!(last, address(order[end]));
                    }
                }
            }
            // Singleton root: exercises the sentinel's final comparison.
            nodes.write(RedBlackTreeNode { color: 0, parent: address(1), left: address(1), right: address(1) });
            nodes.add(1).write(RedBlackTreeNode { color: 0, parent: address(0), left: 0, right: 0 });
            let mut count = 9;
            assert_eq!(red_black_tree_range_count(&address(1), &address(0), &mut count), 1);
            assert_eq!(count, 10);
        }
    }
}
