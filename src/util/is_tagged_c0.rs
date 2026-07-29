//! The 0xc0 top-byte tag test — `FUN_0811d208` @ 0x0811d208 (20 bytes;
//! 11 `bl` call sites).
//!
//! A pure leaf used by the 0x0811bxxx range of code as a guard on opaque
//! u32 handles: values whose top byte is exactly 0xc0 are recognised as
//! "tagged" and take the short path, everything else is resolved through
//! a table lookup. What the tag *means* (an address range? a packed type
//! tag?) is not established — the function is ported on its observable
//! behavior only.
//!
//! The original is five instructions:
//!
//! ```text
//! and  r0, r0, #0xff000000
//! cmp  r0, #0xc0000000
//! movne r0, #0
//! moveq r0, #1
//! bx   lr
//! ```

/// is_tagged_c0 — original: `FUN_0811d208` @ 0x0811d208 (20 bytes).
///
/// Returns 1 when the top byte of `value` is exactly `0xc0`, else 0.
/// All 24 lower bits are masked off before the compare, so e.g.
/// `0xc000_0001` counts as tagged and `0x41c0_0000` does not.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn is_tagged_c0(value: u32) -> u32 {
    u32::from(value & 0xff00_0000 == 0xc000_0000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_tag_is_recognised() {
        assert_eq!(is_tagged_c0(0xc000_0000), 1);
    }

    #[test]
    fn lower_bits_are_ignored() {
        assert_eq!(is_tagged_c0(0xc0ff_ffff), 1);
        assert_eq!(is_tagged_c0(0xc012_3456), 1);
        assert_eq!(is_tagged_c0(0xc000_0001), 1);
    }

    #[test]
    fn any_other_top_byte_is_rejected() {
        assert_eq!(is_tagged_c0(0x0000_0000), 0);
        assert_eq!(is_tagged_c0(0xbf00_0000), 0);
        assert_eq!(is_tagged_c0(0xc100_0000), 0);
        assert_eq!(is_tagged_c0(0xffff_ffff), 0);
    }

    #[test]
    fn the_tag_must_be_the_top_byte_not_just_present() {
        // 0xc0 anywhere but bits 24..=31 does not count.
        assert_eq!(is_tagged_c0(0x00c0_0000), 0);
        assert_eq!(is_tagged_c0(0x0000_c000), 0);
        assert_eq!(is_tagged_c0(0x0000_00c0), 0);
    }

    #[test]
    fn exhaustive_top_byte_sweep() {
        for top in 0u32..=0xff {
            let expected = u32::from(top == 0xc0);
            assert_eq!(is_tagged_c0(top << 24), expected, "top byte {top:#04x}");
            assert_eq!(is_tagged_c0((top << 24) | 0x00ab_cdef), expected, "top byte {top:#04x}");
        }
    }
}
