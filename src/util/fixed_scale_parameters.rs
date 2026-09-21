//! Fixed scale-parameter initialization.

/// `initialize_fixed_scale_parameters` — original: `FUN_082bc8e4` @
/// **0x082bc8e4** (44 bytes exactly, `0x082bc8e4..0x082bc90f`;
/// `0x082bc910` begins the next independent function).
///
/// Raw ARM decoding verifies **three direct inbound plain `bl` call sites**
/// (0x080d99d4, 0x080dd334, and 0x080e3b44), zero predicated inbound calls,
/// and one outbound plain `bl` to `__rt_udiv` @ 0x08036f14. The routine stores
/// fixed scale factors 63 and 255, then stores `63 * 255 / divisor` through
/// `scaled_count`. The quotient remains in r0 on return.
///
/// Deliberate deviations: Rust names the otherwise unidentified scale fields;
/// the port returns the retained r0 quotient rather than the decompiler's
/// `void` signature.
///
/// # Safety
///
/// `scale_numerator`, `scale_denominator`, and `scaled_count` must be valid,
/// aligned writable `u32` pointers. `divisor` must be nonzero, matching the
/// retail unsigned-divider precondition.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.initialize_fixed_scale_parameters")]
#[inline(never)]
pub unsafe extern "C" fn initialize_fixed_scale_parameters(
    divisor: u32,
    scale_numerator: *mut u32,
    scale_denominator: *mut u32,
    scaled_count: *mut u32,
) -> u32 {
    scale_numerator.write(63);
    scale_denominator.write(255);
    let quotient = crate::runtime::rt_div::__rt_udiv(63 * 255, divisor);
    scaled_count.write(quotient);
    quotient
}

#[cfg(test)]
mod tests {
    use super::initialize_fixed_scale_parameters;

    #[test]
    fn initializes_constants_and_scaled_count_at_divisor_boundaries() {
        for (divisor, expected) in [(1, 16_065), (63, 255), (255, 63), (16_065, 1), (16_066, 0), (u32::MAX, 0)] {
            let mut numerator = u32::MAX;
            let mut denominator = u32::MAX;
            let mut count = u32::MAX;

            let returned = unsafe {
                initialize_fixed_scale_parameters(divisor, &mut numerator, &mut denominator, &mut count)
            };

            assert_eq!(numerator, 63);
            assert_eq!(denominator, 255);
            assert_eq!(count, expected);
            assert_eq!(returned, expected);
        }
    }

    #[test]
    fn writes_only_the_three_supplied_words() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0x5555_5555];

        unsafe {
            initialize_fixed_scale_parameters(3, words.as_mut_ptr().add(1), words.as_mut_ptr().add(2), words.as_mut_ptr().add(3));
        }

        assert_eq!(words, [0x1111_1111, 63, 255, 5_355, 0x5555_5555]);
    }
}
