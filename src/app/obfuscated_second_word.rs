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

/// Obfuscated status-word identity — `FUN_08027650` @ 0x08027650.
///
/// True size: 8 bytes, [0x08027650,0x08027658). Raw words e1a00001
/// e12fff1e decode as MOV r0,r1; BX LR; the next entry is independently
/// called. Whole-image aligned A32 decoding verifies two plain inbound BLs
/// (0x082fa850, 0x0831311c), zero predicated BLs, and zero outgoing calls.
/// Return all 32 bits of the second word, ignore the first, access no memory.
/// Both callers pass a byte-masked obfuscated status and subsequently
/// multiply and mask the result; the helper itself performs no narrowing.
/// No behavioral deviations or callee seams. A dedicated text section
/// retains this patch target separately from the identical 0x08027660 body.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_status_word_identity")]
#[inline(never)]
pub extern "C" fn obfuscated_status_word_identity(_ignored_word: u32, status_word: u32) -> u32 {
    status_word
}

/// Obfuscated arithmetic-word identity — `FUN_08027630` @ 0x08027630.
///
/// True size: 8 bytes, [0x08027630,0x08027638). Raw e1a00001 e12fff1e
/// is MOV r0,r1; BX LR. The next real entry has an independent BL at
/// 0x082fc3bc. Whole-image aligned A32 decoding verifies two plain inbound
/// BLs (0x082f8f64, 0x08332b54), zero predicated BLs, and no outgoing calls.
/// Return the second word unchanged, ignore the first, and access no memory.
/// Both callers supply byte-masked arithmetic results and then multiply and
/// mask the return; the helper itself preserves all 32 bits. No behavioral
/// deviations or callee seams. A dedicated section retains a distinct BL
/// target from the neighboring identical identities.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_arithmetic_word_identity")]
#[inline(never)]
pub extern "C" fn obfuscated_arithmetic_word_identity(_ignored_word: u32, arithmetic_word: u32) -> u32 {
    arithmetic_word
}

/// Obfuscated byte-arithmetic identity — `FUN_08027620` @ 0x08027620.
///
/// True size: 8 bytes, [0x08027620,0x08027628). Raw words e1a00001
/// e12fff1e decode as MOV r0,r1; BX LR. The next real entry has independent
/// BLs at 0x082f91f4 and 0x08332acc. Whole-image aligned A32 decoding finds
/// two plain inbound BLs (0x083437b0, 0x083486ac), zero predicated BLs,
/// and zero outgoing calls. Ignore the first word and return all bits of
/// the second without memory access. Both obfuscated callers mask r1 to
/// a byte, then multiply and mask the result; this helper does not narrow.
/// No behavioral deviations or callee seams. A dedicated text section
/// retains a distinct patch target from the other second-word identities.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.obfuscated_byte_arithmetic_identity")]
#[inline(never)]
pub extern "C" fn obfuscated_byte_arithmetic_identity(_ignored_word: u32, arithmetic_word: u32) -> u32 {
    arithmetic_word
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_arithmetic_identity_preserves_full_word_and_ignores_first() {
        for ignored in [0, 1, 0x0800_0001, 0x8000_0000, u32::MAX] {
            for word in [0, 1, 0xff, 0x100, 0x7fff_ffff, 0x8000_0000,
                         u32::MAX, 0xaaaa_aaaa, 0x5555_5555] {
                assert_eq!(obfuscated_byte_arithmetic_identity(ignored, word), word);
            }
            for bit in 0..32 {
                let word = 1u32 << bit;
                assert_eq!(obfuscated_byte_arithmetic_identity(ignored, word), word);
                assert_eq!(obfuscated_byte_arithmetic_identity(ignored, !word), !word);
            }
        }
    }

    #[test]
    fn arithmetic_identity_does_not_narrow_or_use_first_word() {
        for ignored in [0, 1, 0x0800_0001, 0x8000_0000, u32::MAX] {
            for word in [0, 1, 0xff, 0x100, 0x7fff_ffff, 0x8000_0000,
                         u32::MAX, 0xaaaa_aaaa, 0x5555_5555] {
                assert_eq!(obfuscated_arithmetic_word_identity(ignored, word), word);
            }
            for bit in 0..32 {
                let word = 1u32 << bit;
                assert_eq!(obfuscated_arithmetic_word_identity(ignored, word), word);
                assert_eq!(obfuscated_arithmetic_word_identity(ignored, !word), !word);
            }
        }
    }

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

    #[test]
    fn status_identity_preserves_bits_beyond_callers_byte_mask() {
        for ignored in [0, 1, 0x0800_0001, 0x8000_0000, u32::MAX] {
            for status in [0, 1, 0xff, 0x100, 0x7fff_ffff, 0x8000_0000,
                           u32::MAX, 0xaaaa_aaaa, 0x5555_5555] {
                assert_eq!(obfuscated_status_word_identity(ignored, status), status);
            }
            for bit in 0..32 {
                let status = 1u32 << bit;
                assert_eq!(obfuscated_status_word_identity(ignored, status), status);
                assert_eq!(obfuscated_status_word_identity(ignored, !status), !status);
            }
        }
    }
}
