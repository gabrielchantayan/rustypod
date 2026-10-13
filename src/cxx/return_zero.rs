//! `return_zero_ignoring_arguments` — retailOS `FUN_080275e8` @ 0x080275e8.
//! True size: 8 bytes, ending at independently called 0x080275f0.
//! Verified incoming calls: 2 plain BLs (0x082f92ac, 0x0833277c),
//! 0 predicated BLs; no outgoing calls.
//!
//! Raw words e3a00000 e12fff1e implement `mov r0,#0; bx lr`.
//! Return zero without inspecting arguments or accessing memory. The two
//! obfuscated callers supply six ABI words; their concrete meanings are
//! unknown. No callee seams or semantic deviations. Exposing the ignored
//! words in the signature preserves the observed caller ABI rather than
//! Ghidra's inferred no-argument prototype.

/// Returns zero even when ignored ABI words contain invalid addresses.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn return_zero_ignoring_arguments(
    _first: u32, _second: u32, _third: u32,
    _fourth: u32, _fifth: u32, _sixth: u32,
) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::return_zero_ignoring_arguments;

    #[test]
    fn ignores_null_unaligned_and_extreme_argument_words() {
        for word in [0, 1, 3, 0x0800_0000, 0x8000_0000, u32::MAX] {
            for position in 0..6 {
                let mut words = [0u32; 6];
                words[position] = word;
                assert_eq!(return_zero_ignoring_arguments(
                    words[0], words[1], words[2], words[3], words[4], words[5],
                ), 0);
            }
        }
        assert_eq!(return_zero_ignoring_arguments(
            u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX,
        ), 0);
    }
}
