//! `code_is_0x10_through_0x1f` — `FUN_0812aebc` @ `0x0812aebc`.
//! True extent: `0x0812aebc..0x0812af10` (84 bytes), ending in BX LR;
//! the next function starts with PUSH {r4, lr} at `0x0812af10`.
//! Raw A32 words verify two plain inbound BLs (`0x081295e0`, `0x08129730`),
//! zero predicated inbound BLs, and zero plain or predicated outbound BLs.
//!
//! Returns u32 one for codes 0x10 through 0x1f, zero for every other word.
//! RetailOS compares all sixteen codes in a predicated equality chain.
//! The caller classifies a byte before retaining it as pending state or
//! processing a pair; the codes' domain meaning is not established.
//! Deliberate deviation: replace the equality chain with an unsigned
//! wrapping range check, preserving the full 32-bit input and 0/1 result.

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn code_is_0x10_through_0x1f(code: u32) -> u32 {
    (code.wrapping_sub(0x10) <= 0x0f) as u32
}

#[cfg(test)]
mod tests {
    use super::code_is_0x10_through_0x1f;

    fn reference(code: u32) -> u32 {
        match code {
            0x11 | 0x19 | 0x12 | 0x1a | 0x15 | 0x1d | 0x16 | 0x1e |
            0x17 | 0x1f | 0x10 | 0x18 | 0x13 | 0x1b | 0x14 | 0x1c => 1,
            _ => 0,
        }
    }

    #[test]
    fn classifies_every_byte_against_original_equality_chain() {
        for code in 0..=255 {
            assert_eq!(code_is_0x10_through_0x1f(code), reference(code), "code={code:#x}");
        }
    }

    #[test]
    fn does_not_truncate_words_or_accept_wrapped_negative_values() {
        for code in [0x100, 0x110, 0x11f, 0x10010, 0x1001f,
                     0x7fffffff, 0x80000000, 0xfffffff0, 0xffffffff] {
            assert_eq!(code_is_0x10_through_0x1f(code), 0, "code={code:#x}");
        }
    }
}
