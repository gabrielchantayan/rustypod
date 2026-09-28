//! `red_black_tree_rightmost_descendant_083b69fc` — original: `FUN_083b69fc` @
//! `0x083b69fc` (20 bytes; true extent `0x083b69fc..0x083b6a10`).
//!
//! Raw `osos.dec` words are `ldr r1,[r0,#0xc]; cmp r1,#0; movne r0,r1;
//! bne 0x083b69fc; bx lr`. The separately linked leftmost-descendant sibling
//! begins at `0x083b6a10`. Independent A32 decoding finds two inbound plain
//! `bl` sites (`0x083bf80c`, `0x083c00c4`) and no predicated inbound `bl`
//! sites; the body has no outbound calls.
//!
//! Algorithm: repeatedly follow the target-width right-child word at node+0x0c
//! until it is NULL, returning the terminal node in r0. Deliberate deviations:
//! none; `u32` retains target pointer width on 64-bit hosts and volatile loads
//! prevent LLVM from changing the observed load sequence.

/// Returns the rightmost node in a non-NULL red-black-tree subtree.
///
/// `node` and every non-NULL right child must be readable target addresses. No
/// NULL input or cycle guard exists, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_rightmost_descendant_083b69fc")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_rightmost_descendant_083b69fc(mut node: u32) -> u32 {
    loop {
        let right = unsafe { (node as *const u32).add(3).read_volatile() };
        if right == 0 {
            return node;
        }
        node = right;
    }
}

#[cfg(test)]
mod tests {
    use super::red_black_tree_rightmost_descendant_083b69fc;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const NODE_SIZE: usize = 16;

    unsafe fn node_at(base: *mut u8, index: usize) -> *mut u32 {
        unsafe { base.add(index * NODE_SIZE).cast() }
    }

    #[test]
    fn returns_root_when_its_right_child_is_null() {
        let Some(base) = try_map_u32_slab(hints::RED_BLACK_TREE_RIGHTMOST_DESCENDANT_083B69FC, NODE_SIZE) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let root = base.cast::<u32>();
        unsafe { root.add(3).write(0) };

        assert_eq!(unsafe { red_black_tree_rightmost_descendant_083b69fc(root as usize as u32) }, root as usize as u32);
    }

    #[test]
    fn follows_each_right_link_and_ignores_left_links() {
        let Some(base) = try_map_u32_slab(hints::RED_BLACK_TREE_RIGHTMOST_DESCENDANT_083B69FC_CHAIN, NODE_SIZE * 4) else {
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
            unsafe { red_black_tree_rightmost_descendant_083b69fc(root as usize as u32) },
            rightmost as usize as u32
        );
    }
}
