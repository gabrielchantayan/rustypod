//! `red_black_tree_rightmost_descendant` — original: `FUN_083b6ad4` @
//! `0x083b6ad4` (20 bytes; true extent `0x083b6ad4..0x083b6ae8`).
//!
//! Raw `osos.dec` words are `ldr r1,[r0,#0xc]; cmp r1,#0; movne r0,r1;
//! bne 0x083b6ad4; bx lr`; `0x083b6ae8` begins the separately linked
//! leftmost-descendant sibling. Branch-immediate decoding verifies two inbound
//! unconditional plain `bl` sites and no predicated inbound `bl` sites.
//! Algorithm: follow each node's target-width right-child word at offset `0x0c`
//! until it is NULL, returning the final node in `r0`.
//!
//! Deliberate deviation: target pointers remain `u32` addresses rather than host
//! pointers, preserving the retailOS four-byte node layout on 64-bit hosts.

/// Returns the rightmost node in a non-NULL red-black-tree subtree.
///
/// `node` and every non-NULL right child must be readable target addresses. No
/// NULL input or cycle guard exists, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_rightmost_descendant")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_rightmost_descendant(mut node: u32) -> u32 {
    loop {
        let right = unsafe { (node as *const u32).add(3).read() };
        if right == 0 {
            return node;
        }
        node = right;
    }
}

#[cfg(test)]
mod tests {
    use super::red_black_tree_rightmost_descendant;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const NODE_SIZE: usize = 16;

    unsafe fn node_at(base: *mut u8, index: usize) -> *mut u32 {
        unsafe { base.add(index * NODE_SIZE).cast() }
    }

    #[test]
    fn returns_root_when_its_right_child_is_null() {
        let Some(base) = try_map_u32_slab(hints::RED_BLACK_TREE_RIGHTMOST_DESCENDANT, NODE_SIZE) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let root = base as usize as u32;

        assert_eq!(unsafe { red_black_tree_rightmost_descendant(root) }, root);
    }

    #[test]
    fn follows_each_right_link_and_ignores_left_links() {
        let Some(base) = try_map_u32_slab(hints::RED_BLACK_TREE_RIGHTMOST_DESCENDANT_CHAIN, NODE_SIZE * 4) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let root = unsafe { node_at(base, 0) };
        let middle = unsafe { node_at(base, 1) };
        let rightmost = unsafe { node_at(base, 2) };
        let ignored_left = unsafe { node_at(base, 3) };
        unsafe {
            root.add(2).write(ignored_left as usize as u32);
            root.add(3).write(middle as usize as u32);
            middle.add(2).write(ignored_left as usize as u32);
            middle.add(3).write(rightmost as usize as u32);
            rightmost.add(2).write(ignored_left as usize as u32);
            rightmost.add(3).write(0);
        }

        assert_eq!(
            unsafe { red_black_tree_rightmost_descendant(root as usize as u32) },
            rightmost as usize as u32
        );
    }
}
