//! `code_is_0x14_or_0x1c` — `FUN_08129b44` @ `0x08129b44`.
//! True extent: `0x08129b44..0x08129b58` (20 bytes), ending in BX LR;
//! the next function starts CMP r0, #0x17 at `0x08129b58`.
//! Raw A32 words verify two plain inbound BLs (`0x08129608`, `0x08129710`),
//! zero predicated inbound BLs, and zero plain or predicated outbound BLs.
//!
//! Returns u32 one exactly for codes 0x14 and 0x1c, zero otherwise.
//! RetailOS uses CMP #0x14, CMPNE #0x1c, MOVEQ #1, MOVNE #0, BX LR.
//! Caller 0x081295a0 classifies input bytes before retaining pending state
//! or processing a pair; the codes' domain meaning is not established.
//! No deliberate behavioral deviations: compare the entire input word,
//! preserving the original 0/1 return ABI rather than narrowing to a byte.

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn code_is_0x14_or_0x1c(code: u32) -> u32 {
    (code == 0x14 || code == 0x1c) as u32
}

#[cfg(test)]
mod tests {
    use super::code_is_0x14_or_0x1c;

    #[test]
    fn classifies_every_byte() {
        for code in 0..=255 {
            let expected = match code { 0x14 | 0x1c => 1, _ => 0 };
            assert_eq!(code_is_0x14_or_0x1c(code), expected, "code={code:#x}");
        }
    }

    #[test]
    fn does_not_truncate_words_or_accept_negative_values() {
        for code in [0x114, 0x11c, 0x10014, 0x1001c, 0x80000014,
                     0x8000001c, 0x7fffffff, 0x80000000, 0xfffffff4, 0xfffffffc,
                     0xffffffff] {
            assert_eq!(code_is_0x14_or_0x1c(code), 0, "code={code:#x}");
        }
    }
}
