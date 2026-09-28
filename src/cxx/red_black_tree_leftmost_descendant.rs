//! Leftmost descendant lookup for a red-black-tree node.
//!
//! `red_black_tree_leftmost_descendant` — original: `FUN_083b6ae8` @
//! `0x083b6ae8` (**20 bytes**, `0x083b6ae8..0x083b6afc`; the next distinct
//! function begins at `0x083b6afc`). Raw ARM words contain zero outgoing plain
//! or predicated `bl` instructions; two inbound plain `bl` call sites are at
//! `0x083c50f8` and `0x083c58f4`. It follows each node's target-width left
//! child word at `+0x08` until that word is zero and returns the last node.
//!
//! Deliberate deviations: none. The target's 32-bit child word is read by word
//! index rather than a host pointer-field offset, so host fixtures remain
//! layout-faithful on 64-bit hosts.

/// Returns the leftmost descendant of `node`.
///
/// # Safety
///
/// `node` and every non-null left child word must identify a valid target
/// red-black-tree node. Each node must provide at least its first three words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_leftmost_descendant(mut node: *mut u32) -> *mut u32 {
    loop {
        let left = unsafe { node.add(2).read() as usize as *mut u32 };
        if left.is_null() {
            return node;
        }
        node = left;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    const NODE_WORDS: usize = 4;

    #[test]
    fn returns_the_terminal_node_across_left_chains() {
        let Some(words) = try_map_u32_slab(hints::RED_BLACK_TREE_LEFTMOST_DESCENDANT, 0x1000) else {
            return;
        };
        let words = words.cast::<u32>();
        unsafe {
            words.write_bytes(0, 0x1000 / core::mem::size_of::<u32>());
            let root = words.add(0 * NODE_WORDS);
            let child = words.add(1 * NODE_WORDS);
            let leaf = words.add(2 * NODE_WORDS);
            root.add(2).write(child as usize as u32);
            child.add(2).write(leaf as usize as u32);

            assert_eq!(red_black_tree_leftmost_descendant(root), leaf);
            assert_eq!(red_black_tree_leftmost_descendant(leaf), leaf);
        }
    }
}
