/// array_index_stride24 — original: `FUN_083e20b0` @ `0x083e20b0` (16 bytes;
/// source: `ipod-decomp/decomp/c/038/083e20b0_FUN_083e20b0.c`).
///
/// Loads the signed 32-bit base word and returns `base + index * 24`, with
/// both arithmetic operations wrapping modulo $2^{32}$ as on the ARM target.
/// The body does not index an array or dereference beyond that initial base
/// word, so the stride's containing object type is not recoverable. Deviation:
/// none.
///
/// # Safety
/// `base_word` must be a valid, aligned readable pointer to one 32-bit word.
/// As in the original, it is not NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn array_index_stride24(base_word: *const i32, index: i32) -> i32 {
    base_word.read().wrapping_add(index.wrapping_mul(0x18))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_index_returns_the_loaded_base_word() {
        let base = -0x1234_5678i32;

        assert_eq!(unsafe { array_index_stride24(&base, 0) }, base);
    }

    #[test]
    fn positive_and_negative_values_scale_by_twenty_four() {
        let positive_base = 0x1234_5678i32;
        let negative_base = -100i32;

        assert_eq!(unsafe { array_index_stride24(&positive_base, 3) }, 0x1234_56c0);
        assert_eq!(unsafe { array_index_stride24(&negative_base, -4) }, -196);
        assert_eq!(unsafe { array_index_stride24(&negative_base, 5) }, 20);
    }

    #[test]
    fn arithmetic_wraps_at_the_signed_32_bit_target_boundary() {
        let maximum = i32::MAX;
        let minimum = i32::MIN;

        assert_eq!(unsafe { array_index_stride24(&maximum, 1) }, i32::MIN + 23);
        assert_eq!(unsafe { array_index_stride24(&minimum, -1) }, i32::MAX - 23);
    }
}
