//! Address-book availability word: `FUN_0829d818` @ 0x0829d818.
//!
//! True extent: 8 bytes, 0x0829d818..0x0829d820; the next function begins
//! with push {r4, r5, lr}. Raw words: e590005c (ldr r0, [r0, #0x5c]),
//! e12fff1e (bx lr). Whole-image aligned ARM BL decoding finds two plain
//! incoming calls (0x08125450, 0x0820a6d4), zero predicated incoming calls,
//! and zero outgoing calls of either kind.
//!
//! Return the object's word at +0x5c unchanged. The first caller gates
//! GotoScreen AddressBook on its nonzero value; the second also tests it
//! for zero. The field's wider meaning is not established. No validation,
//! boolean normalization, mutation, or deliberate behavioral deviations.

/// Read the word used by retailOS to gate address-book availability.
///
/// # Safety
/// `context` must be non-null, four-byte aligned, and readable through
/// byte offset 0x5f. No live mutable reference may alias the loaded word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn address_book_availability_word(context: *const u32) -> u32 {
    context.add(0x5c / 4).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_exact_field_and_preserves_non_boolean_values() {
        let mut words = [0x5a5a_a5a5u32; 25];
        for value in [0, 1, 2, 0x8000_0000, u32::MAX] {
            words[23] = value;
            let before = words;
            assert_eq!(unsafe { address_book_availability_word(words.as_ptr()) }, value);
            assert_eq!(words, before);
        }
    }

    #[test]
    fn reads_last_word_of_minimum_sized_object_at_shifted_base() {
        let mut words = [0xdead_beefu32; 25];
        words[23] = 0x1234_5678;
        words[24] = 0xfedc_ba98;
        let context = unsafe { words.as_ptr().add(1) };
        assert_eq!(unsafe { address_book_availability_word(context) }, 0xfedc_ba98);
    }
}
