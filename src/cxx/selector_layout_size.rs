//! selector_layout_size — `FUN_08266b64` @ 0x08266b64.
//! True size: 32 bytes, eight ARM words, ending at the next push at
//! 0x08266b84. Verified raw A32: two plain inbound BLs (0x083d97c0,
//! 0x083d9d7c), zero predicated inbound BLs, zero outbound BLs of either kind.
//!
//! Returns the standard-stream wrapper's selector-dependent layout size:
//! selector zero maps to four bytes, one or two to eight, all other full-width
//! values to twelve. Only equality comparisons matter; no validation or
//! signed interpretation is imposed. Deliberate deviations: none.

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn selector_layout_size(selector: u32) -> u32 {
    match selector {
        0 => 4,
        1 | 2 => 8,
        _ => 12,
    }
}

#[cfg(test)]
mod tests {
    use super::selector_layout_size;

    #[test]
    fn standard_stream_selectors_and_first_invalid_value() {
        for (selector, size) in [(0, 4), (1, 8), (2, 8), (3, 12)] {
            assert_eq!(selector_layout_size(selector), size);
        }
    }

    #[test]
    fn invalid_selectors_are_compared_at_full_width() {
        for selector in [4, 0x100, 0x101, 0x102, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            assert_eq!(selector_layout_size(selector), 12);
        }
    }
}
