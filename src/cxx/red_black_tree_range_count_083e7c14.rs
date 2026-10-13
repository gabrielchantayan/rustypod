//! Red-black-tree iterator range distance accumulation.
//!
//! Original `FUN_083e7c14` at load address `0x083e7c14`: true size 156
//! bytes, through the return at `0x083e7cac`; next function `0x083e7cb0`.
//! Full-image aligned A32 decoding verifies one plain inbound BL at
//! `0x083d7328`, zero predicated inbound BLs, and no outbound BLs.
//! Adds the in-order distance [first, last) to an existing wrapping counter.
//! Descends right-child left spines or climbs parents, retaining the header
//! sentinel comparison. Neither iterator is modified; last is reloaded each
//! iteration. Returns 1 (raw r0), contrary to Ghidra's void signature.
//! Deliberate deviations: none. The firmware body is byte-identical to
//! `0x083e7cb0`; LLVM folds these exports to the same object and address.
//! match.py cannot extract the alias label; comparison via the primary
//! `red_black_tree_range_count` label verifies the shared 33-instruction body.

use super::red_black_tree_increment::RedBlackTreeNode;

/// # Safety
/// Iterator words and count must be aligned readable memory, count writable.
/// The range must be reachable through valid target-width tree links and its
/// header sentinel. The counter may alias last, which is reloaded each time.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_range_count_083e7c14(
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
    fn empty_range_preserves_counter_without_reading_node() {
        let cursor = 0u32;
        let mut count = u32::MAX;
        assert_eq!(unsafe { red_black_tree_range_count_083e7c14(&cursor, &cursor, &mut count) }, 1);
        assert_eq!(count, u32::MAX);
    }

    #[test]
    fn skewed_tree_subranges_wrap_and_preserve_cursors() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::RED_BLACK_TREE_RANGE_COUNT_083E7C14, 0x1000,
        ).expect("target-width tree fixture");
        let nodes = slab.cast::<RedBlackTreeNode>();
        unsafe {
            let address = |index: usize| nodes.add(index) as usize as u32;
            // Both left- and right-skewed trees, including their header.
            for left_skew in [false, true] {
                let root = if left_skew { 4 } else { 1 };
                nodes.write(RedBlackTreeNode { color: 0, parent: address(root), left: address(1), right: address(4) });
                for index in 1..=4 {
                    let parent = if index == root { 0 } else if left_skew { index + 1 } else { index - 1 };
                    nodes.add(index).write(RedBlackTreeNode {
                        color: 0, parent: address(parent),
                        left: if left_skew && index > 1 { address(index - 1) } else { 0 },
                        right: if !left_skew && index < 4 { address(index + 1) } else { 0 },
                    });
                }
                let order = [1, 2, 3, 4, 0];
                for start in 0..order.len() {
                    for end in start..order.len() {
                        let first = address(order[start]);
                        let last = address(order[end]);
                        let mut count = u32::MAX - 1;
                        assert_eq!(red_black_tree_range_count_083e7c14(&first, &last, &mut count), 1);
                        assert_eq!(count, (u32::MAX - 1).wrapping_add((end - start) as u32));
                        assert_eq!(first, address(order[start]));
                        assert_eq!(last, address(order[end]));
                    }
                }
                // Aliased end/counter changes from header-1 to header after
                // one increment. Caching last would walk beyond the header.
                let first = address(4);
                let mut end_count = address(0) - 1;
                let shared = &mut end_count as *mut u32;
                assert_eq!(red_black_tree_range_count_083e7c14(&first, shared, shared), 1);
                assert_eq!(end_count, address(0));
            }
        }
    }
}
