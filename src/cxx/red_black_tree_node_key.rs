//! `red_black_tree_node_key` — original: `FUN_083b6a54` @ `0x083b6a54`
//! (8 bytes; true extent `0x083b6a54..0x083b6a5c`).
//!
//! Raw `osos.dec` words `e2800010 e12fff1e` establish the complete A32 body:
//! `add r0,r0,#0x10; bx lr`. The next separately linked function begins at
//! `0x083b6a5c`. The body has zero plain `bl` and zero predicated `bl`
//! instructions. Independent whole-image decoding finds two inbound plain
//! `bl` calls, at `0x083ba750` and `0x083d72bc`, and zero predicated inbound
//! calls.
//!
//! Returns the address of a red-black-tree node's key payload at byte offset
//! `0x10`. No pointer is dereferenced and no null guard exists. Deliberate
//! deviation: none; wrapping addition preserves ARM's modulo-2^32 result.

/// Returns the target-width address of `node`'s key payload at +0x10.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn red_black_tree_node_key(node: u32) -> u32 {
    node.wrapping_add(0x10)
}

#[cfg(test)]
mod tests {
    use super::red_black_tree_node_key;

    #[test]
    fn adds_the_key_payload_offset_with_arm_wrapping() {
        assert_eq!(red_black_tree_node_key(0), 0x10);
        assert_eq!(red_black_tree_node_key(0x083b_7000), 0x083b_7010);
        assert_eq!(red_black_tree_node_key(u32::MAX), 0x0f);
        assert_eq!(red_black_tree_node_key(0xffff_fff0), 0);
    }
}
