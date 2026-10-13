//! Second-word identity — `FUN_08027660` @ 0x08027660.
//!
//! Executable size: 8 bytes (`e1a00001 e12fff1e`: MOV r0,r1; BX LR).
//! Boundary extent: 56 bytes, [0x08027660,0x08027698). The trailing twelve
//! BX LR words have no inbound aligned branches or address literals; the next
//! real entry at 0x08027698 has four independent branch references.
//! Whole-image aligned A32 decoding verifies two plain inbound BLs at
//! 0x08343990 and 0x08348784, zero predicated BLs, and zero outgoing calls.
//!
//! Return the second ABI word unchanged, ignoring the first and accessing no
//! memory. Both callers are obfuscated state machines that consume the result
//! in byte-masked arithmetic; no narrower type or callee identity is assumed.
//! No behavioral deviations. Unreachable trailing words are not reproduced.
//! A dedicated text section keeps this independently patchable BL target.

/// Select the second opaque 32-bit word without interpreting either input.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_second_word")]
#[inline(never)]
pub extern "C" fn obfuscated_second_word(_ignored_word: u32, result_word: u32) -> u32 {
    result_word
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_first_word_and_preserves_full_width_second_word() {
        for ignored in [0, 1, 0x0800_0001, 0x8000_0000, u32::MAX] {
            for result in [0, 1, 0xff, 0x100, 0x8000_0000, u32::MAX,
                           0xaaaa_aaaa, 0x5555_5555] {
                assert_eq!(obfuscated_second_word(ignored, result), result);
            }
            for bit in 0..32 {
                let result = 1u32 << bit;
                assert_eq!(obfuscated_second_word(ignored, result), result);
                assert_eq!(obfuscated_second_word(ignored, !result), !result);
            }
        }
    }
}
