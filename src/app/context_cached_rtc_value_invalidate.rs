//! Invalidate the context's cached RTC value.
//! Original FUN_08116d54 @ 0x08116d54, true size 12 bytes; next function
//! begins at 0x08116d60. Whole-image aligned A32 scan verifies two incoming
//! plain BLs (0x08202f1c, 0x0820e810), zero predicated incoming BLs and
//! zero outgoing calls.
//!
//! Store the invalid sentinel (-1) in the word at context +0x738.
//! This word caches the value read from the RTC object at +0x88c via
//! virtual slot +0x88; restoration tests -1 before using slot +0x84.
//! Original words: e3e01000 e5801738 e12fff1e. No target behavioral
//! deviations. Return the context pointer to preserve the original r0;
//! Ghidra's void signature hides that register pass-through.

/// # Safety
/// `context` must point into a live allocation with a writable, four-byte
/// aligned u32 at byte offset 0x738. No null guard exists in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_cached_rtc_value_invalidate(context: *mut u8) -> *mut u8 {
    context.add(0x738).cast::<u32>().write(u32::MAX);
    context
}

#[cfg(test)]
mod tests {
    use super::context_cached_rtc_value_invalidate;

    #[test]
    fn replaces_full_word_preserves_neighbors_and_receiver() {
        for previous in [0, 1, 0x7fffffff, 0x80000000, 0x12345678, u32::MAX] {
            // Native u32 words retain the firmware's four-byte field spacing.
            let mut words = [0xa5c39e71u32; 0x738 / 4 + 2];
            words[0x738 / 4] = previous;
            let mut expected = words;
            expected[0x738 / 4] = u32::MAX;
            let context = words.as_mut_ptr().cast::<u8>();
            let returned = unsafe { context_cached_rtc_value_invalidate(context) };
            assert_eq!(returned, context);
            assert_eq!(words, expected);
            // Invalidating an already-invalid cache is idempotent.
            unsafe { context_cached_rtc_value_invalidate(context); }
            assert_eq!(words, expected);
        }
    }
}
