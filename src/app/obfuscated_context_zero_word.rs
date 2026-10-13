//! Constant-zero context word — `FUN_08027648` @ 0x08027648.
//!
//! True size: 8 bytes, [0x08027648,0x08027650). Raw words e3a00000
//! e12fff1e are MOV r0,#0; BX LR. The next real entry has independent BLs.
//! Whole-image aligned A32 decoding verifies two plain inbound BLs at
//! 0x082fa98c and 0x08312f78, zero predicated BLs, and zero outgoing calls.
//!
//! Return zero, ignoring the six opaque words supplied by the obfuscated
//! state machines FUN_082fa514 and FUN_08312b70. Read no memory; concrete
//! argument types and higher-level context semantics remain unknown.
//! No behavioral deviations or callee seams. Inline-never and a dedicated
//! text section retain a separate patch target from the identical helper
//! at 0x08027658.

/// Produce a zero context word without interpreting any caller input.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_context_zero_word")]
#[inline(never)]
pub extern "C" fn obfuscated_context_zero_word(
    _first: u32, _second: u32, _third: u32,
    _fourth: u32, _fifth: u32, _sixth: u32,
) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discards_register_and_stack_words_including_invalid_addresses() {
        let edges = [0, 1, 0xff, 0x100, 0x0800_0001, 0x8000_0000,
                     u32::MAX, 0xaaaa_aaaa, 0x5555_5555];
        for position in 0..6 {
            for word in edges {
                let mut words = [u32::MAX; 6];
                words[position] = word;
                assert_eq!(obfuscated_context_zero_word(words[0], words[1], words[2],
                                                       words[3], words[4], words[5]), 0);
            }
        }
        assert_eq!(obfuscated_context_zero_word(0, 0, 0, 0, 0, 0), 0);
    }
}
