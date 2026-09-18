//! Three-word resource-reference initializer.

/// resource_ref_clear — original: `FUN_081e170c` @ 0x081e170c
/// (**20 bytes**, `0x081e170c..0x081e171f`; the independently linked
/// comparison leaf begins at 0x081e1720). Four inbound direct `bl` calls,
/// all plain unconditional and none predicated, are binary-verified at
/// 0x081861f8, 0x081b9684, 0x08288fc8, and 0x08291c44.
///
/// Writes zero to the three consecutive target words at offsets +0, +4, and
/// +8, then returns `resource_ref` unchanged. No deliberate deviations.
///
/// # Safety
///
/// `resource_ref` must point to three writable, 4-byte-aligned `u32` words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_ref_clear(resource_ref: *mut u32) -> *mut u32 {
    resource_ref.write_volatile(0);
    resource_ref.add(1).write_volatile(0);
    resource_ref.add(2).write_volatile(0);
    resource_ref
}

#[cfg(test)]
mod tests {
    use super::resource_ref_clear;

    #[test]
    fn clears_only_the_three_word_resource_reference() {
        let mut words = [0x1122_3344, 0xffff_ffff, 0x5566_7788, 0xa5a5_a5a5, 0x89ab_cdef];
        let resource_ref = unsafe { words.as_mut_ptr().add(1) };

        let returned = unsafe { resource_ref_clear(resource_ref) };

        assert_eq!(returned, resource_ref);
        assert_eq!(words, [0x1122_3344, 0, 0, 0, 0x89ab_cdef]);
    }
}
