//! object_word_0xc0 — original: `FUN_08142910` @ 0x08142910 (8 bytes;
//! five unconditional `bl` call sites, zero predicated `bl` call sites,
//! binary-scanned).
//!
//! Raw `osos.dec` words establish the complete function: `ldr r0,[r0,#0xc0]`
//! at 0x08142910 and `bx lr` at 0x08142914. The next separately linked
//! function starts at 0x08142918. It returns the unchecked object's word at
//! byte offset 0xc0. Callers use the result as a signed value, but the load
//! itself has no signed interpretation.
//!
//! Deliberate deviations: none. The unchecked dereference intentionally
//! retains the firmware's null and invalid-pointer fault behavior.

/// Returns the word at byte offset 0xc0 of `object`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_word_0xc0(object: *const u32) -> u32 {
    *object.add(0x30)
}

#[cfg(test)]
mod tests {
    use super::object_word_0xc0;

    #[test]
    fn reads_the_word_at_offset_0xc0_without_adjacent_words() {
        let mut object = [0x5555_5555u32; 0x31];
        object[0x2f] = 0x1234_5678;
        object[0x30] = 0x89ab_cdef;

        assert_eq!(unsafe { object_word_0xc0(object.as_ptr()) }, 0x89ab_cdef);
    }

    #[test]
    fn preserves_word_bits_without_signed_interpretation() {
        let mut object = [0u32; 0x31];
        object[0x30] = 0x8000_0000;
        assert_eq!(unsafe { object_word_0xc0(object.as_ptr()) }, 0x8000_0000);

        object[0x30] = u32::MAX;
        assert_eq!(unsafe { object_word_0xc0(object.as_ptr()) }, u32::MAX);
    }
}
