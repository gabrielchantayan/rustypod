//! FreeType conditional offset adjustment helper.

/// Writes an adjusted nonzero offset and reports whether an offset was present.
///
/// `ft_adjust_offset_if_nonzero` — original: `FUN_0802de50` @ `0x0802de50`
/// (40 bytes).
///
/// A zero `offset` means no optional field is present: the function returns 0
/// without dereferencing `adjusted_offset`. Otherwise it adds 4 for a zero
/// `bias_selector`, or 0x1004 for a nonzero selector, using ARM's wrapping
/// 32-bit addition; it stores that value through `adjusted_offset` and returns
/// 1.
///
/// # Safety
/// When `offset` is nonzero, `adjusted_offset` must be valid for a `u32`
/// write. It need not be valid when `offset` is zero because the original does
/// not dereference it on that path.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_adjust_offset_if_nonzero(
    bias_selector: u32,
    offset: u32,
    adjusted_offset: *mut u32,
) -> u32 {
    if offset == 0 {
        return 0;
    }

    let bias = if bias_selector == 0 { 4 } else { 0x1004 };
    core::ptr::write(adjusted_offset, offset.wrapping_add(bias));
    1
}

#[cfg(test)]
mod tests {
    use super::ft_adjust_offset_if_nonzero;

    #[test]
    fn zero_selector_adds_the_small_offset() {
        let mut adjusted = 0;
        assert_eq!(unsafe { ft_adjust_offset_if_nonzero(0, 0x1200, &mut adjusted) }, 1);
        assert_eq!(adjusted, 0x1204);
    }

    #[test]
    fn nonzero_selector_adds_the_large_offset() {
        let mut adjusted = 0;
        assert_eq!(unsafe { ft_adjust_offset_if_nonzero(1, 0x1200, &mut adjusted) }, 1);
        assert_eq!(adjusted, 0x2204);
    }

    #[test]
    fn arithmetic_wraps_like_the_arm_add_instructions() {
        let mut adjusted = 0;
        assert_eq!(unsafe { ft_adjust_offset_if_nonzero(0, u32::MAX - 1, &mut adjusted) }, 1);
        assert_eq!(adjusted, 2);

        assert_eq!(unsafe { ft_adjust_offset_if_nonzero(0xfeed, u32::MAX - 3, &mut adjusted) }, 1);
        assert_eq!(adjusted, 0x1000);
    }

    #[test]
    fn zero_offset_returns_zero_without_writing_the_output() {
        let mut adjusted = 0xdead_beef;
        assert_eq!(unsafe { ft_adjust_offset_if_nonzero(0, 0, &mut adjusted) }, 0);
        assert_eq!(adjusted, 0xdead_beef);

        // The no-offset branch returns before dereferencing this invalid
        // pointer, just as the original's early `bxeq lr` does.
        assert_eq!(unsafe { ft_adjust_offset_if_nonzero(1, 0, core::ptr::null_mut()) }, 0);
    }
}
