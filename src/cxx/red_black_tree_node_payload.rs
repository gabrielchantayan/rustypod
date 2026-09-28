//! `red_black_tree_node_payload` — original: `FUN_083b6b4c` @ `0x083b6b4c`
//! (8 bytes; `0x083b6b4c..0x083b6b54`).
//!
//! Raw ARM is `add r0,r0,#0x10; bx lr`. The next real function begins with
//! `push {r4-r8,lr}` at `0x083b6b54`, establishing the exact two-word extent.
//! The function has no outbound calls. Independent A32 decoding finds exactly
//! two inbound direct calls, both unconditional plain `bl` (at `0x083cc9c8`
//! and `0x083dbf74`); there are no predicated `bl` calls. It returns the
//! address of a red-black-tree node's payload, 16 bytes after its header.
//! No deliberate deviations.

/// red_black_tree_node_payload — original: `FUN_083b6b4c` @ `0x083b6b4c`
/// (8 bytes; 2 direct plain-`bl` call sites).
///
/// Returns the address immediately following the 16-byte red-black-tree node
/// header. The ARM `add` wraps modulo $2^{32}$; `wrapping_add` retains that
/// behavior when this port is built for its 32-bit target.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_node_payload")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_node_payload(node: *mut u8) -> *mut u8 {
    node.wrapping_add(16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_payload_after_the_16_byte_node_header() {
        let mut node = [0u8; 20];
        assert_eq!(
            unsafe { red_black_tree_node_payload(node.as_mut_ptr()) },
            node.as_mut_ptr().wrapping_add(16),
        );
    }

    #[test]
    fn preserves_the_arm_wraparound_address_arithmetic() {
        let near_end = (usize::MAX - 7) as *mut u8;
        assert_eq!(
            unsafe { red_black_tree_node_payload(near_end) },
            near_end.wrapping_add(16),
        );
    }
}
