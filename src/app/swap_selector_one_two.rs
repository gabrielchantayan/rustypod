//! `swap_selector_one_two` — original: `FUN_0817c044` @ `0x0817c044`
//! (40 bytes).
//!
//! # Algorithm
//!
//! Ignores its first ABI argument and maps selector `1` to `2`, selector `2`
//! to `1`, and every other `u32` value to `0`. The stock A32 body uses two
//! conditional returns before its zero default.
//!
//! Verified from raw `osos.dec`: `0x0817c044..0x0817c06b`; the `push
//! {r4,r6,lr}` at `0x0817c06c` begins the next real function. The body has
//! zero plain `bl`, zero predicated `bl`, and no `blx` instructions. It has
//! three inbound plain `bl` sites and zero predicated inbound `bl` sites.
//!
//! Deliberate deviation: Rust expresses the conditional returns as a `match`;
//! the ignored first argument remains in the ABI for the retailOS callers.

/// Returns the counterpart of selector values one and two, or zero.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn swap_selector_one_two(_context: u32, selector: u32) -> u32 {
    match selector {
        1 => 2,
        2 => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::swap_selector_one_two;

    #[test]
    fn swaps_only_the_first_two_selectors() {
        let cases = [
            (0, 0),
            (1, 2),
            (2, 1),
            (3, 0),
            (u32::MAX, 0),
        ];

        for (selector, expected) in cases {
            assert_eq!(unsafe { swap_selector_one_two(0x1234_5678, selector) }, expected);
        }
    }
}
