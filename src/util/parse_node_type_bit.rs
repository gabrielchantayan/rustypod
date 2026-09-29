//! `parse_node_type_bit` — original: `FUN_082dc26c` @ `0x082dc26c`.
//!
//! Verified extent is exactly `0x082dc26c..0x082dc290` (36 bytes): the next
//! separately linked function begins at `0x082dc290` with `ldr r2,[r0]`.
//! Whole-image A32 decoding finds two inbound unconditional plain `bl` sites,
//! no predicated `bl` sites, and no direct calls in this body.
//!
//! Converts the parser node type to its bit flag: `0x40` maps to bit 0,
//! `0x41` maps to bit 7, and every other value maps to bit `type - 0x43`.
//! ARM's register-controlled shift uses the low byte and produces zero for
//! shift counts at least 32.
//!
//! # Deliberate deviations
//!
//! None.

/// Converts a retailOS parser node type into its associated bit flag.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.parse_node_type_bit")]
#[inline(never)]
pub extern "C" fn parse_node_type_bit(node_type: u32) -> u32 {
    match node_type {
        0x40 => 1,
        0x41 => 0x80,
        _ => {
            let shift = node_type.wrapping_sub(0x44) & 0xff;
            if shift < 32 { 2 << shift } else { 0 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_special_and_contiguous_node_types() {
        assert_eq!(parse_node_type_bit(0x40), 1);
        assert_eq!(parse_node_type_bit(0x41), 0x80);
        assert_eq!(parse_node_type_bit(0x44), 2);
        assert_eq!(parse_node_type_bit(0x45), 4);
        assert_eq!(parse_node_type_bit(0x62), 0x8000_0000);
    }

    #[test]
    fn matches_arm_register_shift_boundaries() {
        assert_eq!(parse_node_type_bit(0x5f), 0x1000_0000);
        assert_eq!(parse_node_type_bit(0x63), 0);
        assert_eq!(parse_node_type_bit(0x64), 0);
        assert_eq!(parse_node_type_bit(0x43), 0);
        assert_eq!(parse_node_type_bit(0), 0);
        assert_eq!(parse_node_type_bit(u32::MAX), 0);
    }
}
