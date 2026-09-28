//! `red_black_tree_leftmost_descendant_083b6a10` — original: `FUN_083b6a10` @
//! `0x083b6a10` (20 bytes; true extent `0x083b6a10..0x083b6a24`).
//!
//! Raw `osos.dec` words are `ldr r1,[r0,#8]; cmp r1,#0; movne r0,r1;
//! bne 0x083b6a10; bx lr`; `0x083b6a24` begins the next independently linked
//! function. Whole-image A32 decoding verifies two inbound unconditional plain
//! `bl` sites (`0x083bf7d4`, `0x083c00b0`) and no predicated inbound `bl`
//! sites. The body has zero outbound plain or predicated `bl` calls. Algorithm:
//! follow each node's target-width left-child word at offset `0x08` until it is
//! NULL, returning the final node in `r0`.
//!
//! Deliberate deviation: target pointers remain `u32` addresses rather than host
//! pointers, preserving the retailOS four-byte node layout on 64-bit hosts.

/// Returns the leftmost node in a non-NULL red-black-tree subtree.
///
/// `node` and every non-NULL left child must be readable target addresses. No
/// NULL input or cycle guard exists, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_leftmost_descendant_083b6a10")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_leftmost_descendant_083b6a10(mut node: u32) -> u32 {
    loop {
        let left = unsafe { (node as *const u32).add(2).read_volatile() };
        if left == 0 {
            return node;
        }
        node = left;
    }
}

#[cfg(test)]
mod tests {
    use super::red_black_tree_leftmost_descendant_083b6a10;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const NODE_SIZE: usize = 16;

    unsafe fn node_at(base: *mut u8, index: usize) -> *mut u32 {
        unsafe { base.add(index * NODE_SIZE).cast() }
    }

    #[test]
    fn returns_root_when_its_left_child_is_null() {
        let Some(base) = try_map_u32_slab(hints::RED_BLACK_TREE_LEFTMOST_DESCENDANT_083B6A10, NODE_SIZE) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let root = base as usize as u32;

        assert_eq!(unsafe { red_black_tree_leftmost_descendant_083b6a10(root) }, root);
    }

    #[test]
    fn follows_each_left_link_and_ignores_right_links() {
        let Some(base) = try_map_u32_slab(hints::RED_BLACK_TREE_LEFTMOST_DESCENDANT_083B6A10_CHAIN, NODE_SIZE * 4) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let root = unsafe { node_at(base, 0) };
        let middle = unsafe { node_at(base, 1) };
        let leftmost = unsafe { node_at(base, 2) };
        let ignored_right = unsafe { node_at(base, 3) };
        unsafe {
            root.add(2).write(middle as usize as u32);
            root.add(3).write(ignored_right as usize as u32);
            middle.add(2).write(leftmost as usize as u32);
            middle.add(3).write(ignored_right as usize as u32);
            leftmost.add(2).write(0);
            leftmost.add(3).write(ignored_right as usize as u32);
        }

        assert_eq!(
            unsafe { red_black_tree_leftmost_descendant_083b6a10(root as usize as u32) },
            leftmost as usize as u32
        );
    }
}
