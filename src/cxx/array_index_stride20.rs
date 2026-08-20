/// array_index_stride20 — original: `FUN_083e0298` @ `0x083e0298` (16 bytes;
/// source: `ipod-decomp/decomp/c/038/083e0298_FUN_083e0298.c`).
///
/// Loads the unsigned 32-bit base word and returns `base + index * 20`, with
/// both operations wrapping modulo $2^{32}$ as on the ARM target. The body
/// does not index an array or dereference beyond that initial base word, so
/// the stride's containing object type is not recoverable. Deviation: none.
///
/// # Safety
/// `base_word` must be a valid, aligned readable pointer to one 32-bit word.
/// As in the original, it is not NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn array_index_stride20(base_word: *const u32, index: u32) -> u32 {
    base_word.read().wrapping_add(index.wrapping_mul(0x14))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_twenty_per_index_to_distinct_base_values() {
        let first = 0x1234_5678u32;
        let second = 0x9abc_def0u32;

        assert_eq!(unsafe { array_index_stride20(&first, 3) }, 0x1234_56b4);
        assert_eq!(unsafe { array_index_stride20(&second, 7) }, 0x9abc_df7c);
    }

    #[test]
    fn zero_index_returns_the_loaded_base_word() {
        let base = 0xdead_beefu32;

        assert_eq!(unsafe { array_index_stride20(&base, 0) }, base);
    }

    #[test]
    fn arithmetic_wraps_at_the_32_bit_target_boundary() {
        let base = u32::MAX - 9;

        assert_eq!(unsafe { array_index_stride20(&base, 1) }, 10);
        assert_eq!(unsafe { array_index_stride20(&base, u32::MAX) }, u32::MAX - 29);
    }
}
