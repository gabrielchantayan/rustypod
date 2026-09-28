//! `word_key_set_node_key` — retailOS `FUN_083b6a2c` @ `0x083b6a2c`
//! (8 bytes; true extent `0x083b6a2c..0x083b6a34`).
//!
//! Raw `osos.dec` words are `add r0,r0,#0x10; bx lr`; the identical leaf at
//! `0x083b6a34` is the next separately linked function, so it is not part of
//! this function. The body has zero outbound plain or predicated `bl` calls.
//! Raw branch-immediate decoding finds two inbound unconditional plain `bl`
//! sites (`0x083c02a0`, `0x083c0964`) and zero predicated inbound `bl` sites.
//! It returns the address of a word-keyed red-black-tree node's `u32` key at
//! offset `0x10`. Deliberate deviation: the host implementation accepts and
//! returns a wrapping target address as `u32`; the target implementation emits
//! the two retail instructions directly.

/// Returns the target address of a word-keyed red-black-tree node's key.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", unsafe(naked))]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_key_set_node_key")]
pub unsafe extern "C" fn word_key_set_node_key() {
    core::arch::naked_asm!("add r0,r0,#0x10", "bx lr");
}

#[cfg(not(target_os = "none"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn word_key_set_node_key(node: u32) -> u32 {
    node.wrapping_add(0x10)
}

#[cfg(test)]
mod tests {
    use super::word_key_set_node_key;

    fn reference(node: u32) -> u32 {
        node.wrapping_add(0x10)
    }

    #[test]
    fn advances_aligned_and_unaligned_target_addresses() {
        for node in [0, 1, 2, 3, 0x0800_0000, 0x083b_6a2c, 0xffff_ffef] {
            assert_eq!(word_key_set_node_key(node), reference(node));
        }
    }

    #[test]
    fn wraps_like_the_arm_add_instruction() {
        assert_eq!(word_key_set_node_key(0xffff_fff0), reference(0xffff_fff0));
        assert_eq!(word_key_set_node_key(u32::MAX), reference(u32::MAX));
    }
}
