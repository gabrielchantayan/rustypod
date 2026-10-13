//! Constant-zero word — `FUN_08027658` @ 0x08027658.
//!
//! True size: 8 bytes, [0x08027658,0x08027660). Raw words are e3a00000
//! e12fff1e (MOV r0,#0; BX LR); the next entry has independent BL callers.
//! Whole-image aligned A32 decoding verifies two plain inbound BLs at
//! 0x08343b84 and 0x08348278, zero predicated BLs, and zero outgoing calls.
//!
//! Return zero without reading memory or interpreting the six opaque ABI
//! words supplied by both obfuscated state-machine callers. Their concrete
//! types are unknown; no callee seams or inferred allocation semantics.
//! No behavioral deviations. A dedicated text section and inline-never keep
//! this independently patchable target distinct from other zero helpers.

/// Discard the caller's opaque words and produce a zero result word.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_zero_word")]
#[inline(never)]
pub extern "C" fn obfuscated_zero_word(
    _first: u32, _second: u32, _third: u32,
    _fourth: u32, _fifth: u32, _sixth: u32,
) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_every_register_and_stack_argument() {
        let edges = [0, 1, 0xff, 0x100, 0x0800_0001, 0x8000_0000,
                     u32::MAX, 0xaaaa_aaaa, 0x5555_5555];
        for position in 0..6 {
            for word in edges {
                let mut words = [u32::MAX; 6];
                words[position] = word;
                assert_eq!(obfuscated_zero_word(words[0], words[1], words[2],
                                               words[3], words[4], words[5]), 0);
            }
        }
        assert_eq!(obfuscated_zero_word(0, 0, 0, 0, 0, 0), 0);
    }
}
