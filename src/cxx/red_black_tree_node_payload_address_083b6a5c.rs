//! `red_black_tree_node_payload_address_083b6a5c` — original: `FUN_083b6a5c` @ `0x083b6a5c`
//! (8 bytes; true extent `0x083b6a5c..0x083b6a64`).
//!
//! Raw `osos.dec` words are `add r0,r0,#0x10; bx lr`; `0x083b6a64` begins the
//! separately linked payload-address helper. The body contains no outbound BL
//! calls. Raw branch-immediate decoding verifies two inbound unconditional
//! plain `bl` sites (`0x08124e64`, `0x083bc734`) and no predicated inbound BL
//! sites. It returns the address of a red-black-tree node's payload at offset
//! `0x10`. Deliberate deviation: the target address remains a wrapping `u32`,
//! rather than a host pointer, preserving ARM address arithmetic and the
//! firmware's four-byte pointer representation.

/// Returns the target address of a red-black-tree node's payload.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", unsafe(naked))]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_node_payload_address_083b6a5c")]
pub unsafe extern "C" fn red_black_tree_node_payload_address_083b6a5c() {
    core::arch::naked_asm!("add r0,r0,#0x10", "bx lr");
}

#[cfg(not(target_os = "none"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn red_black_tree_node_payload_address_083b6a5c(node: u32) -> u32 {
    node.wrapping_add(0x10)
}

#[cfg(test)]
mod tests {
    use super::red_black_tree_node_payload_address_083b6a5c;

    fn reference(node: u32) -> u32 {
        node.wrapping_add(0x10)
    }

    #[test]
    fn advances_aligned_and_unaligned_target_addresses() {
        for node in [0, 1, 2, 3, 0x0800_0000, 0x083b_6a5c, 0xffff_ffef] {
            assert_eq!(red_black_tree_node_payload_address_083b6a5c(node), reference(node));
        }
    }

    #[test]
    fn wraps_like_the_arm_add_instruction() {
        assert_eq!(
            red_black_tree_node_payload_address_083b6a5c(0xffff_fff0),
            reference(0xffff_fff0)
        );
        assert_eq!(
            red_black_tree_node_payload_address_083b6a5c(u32::MAX),
            reference(u32::MAX)
        );
    }
}
