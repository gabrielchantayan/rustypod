//! Q16.16 three-component vector helpers.

/// `copy_fixed16_vec3` — original: `FUN_0824c6d8` @ 0x0824c6d8 (28 bytes).
///
/// Copies the three Q16.16 component words from `src` to `dst` in forward
/// order. Raw `osos.dec` establishes the extent 0x0824c6d8..0x0824c6f4: the
/// next function starts with `ldr r2, [r0]` at 0x0824c6f4. It has four plain,
/// unconditional inbound `bl` sites (0x0824bfe0, 0x0824bfec, 0x08255238, and
/// 0x0825525c), no predicated `bl` sites, and no calls itself. The volatile
/// accesses deliberately preserve the original load/store order for partially
/// overlapping pointers; no deliberate behavioral deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_fixed16_vec3")]
pub unsafe extern "C" fn copy_fixed16_vec3(dst: *mut i32, src: *const i32) {
    core::ptr::write_volatile(dst, core::ptr::read_volatile(src));
    core::ptr::write_volatile(dst.add(1), core::ptr::read_volatile(src.add(1)));
    core::ptr::write_volatile(dst.add(2), core::ptr::read_volatile(src.add(2)));
}

#[cfg(test)]
mod tests {
    use super::copy_fixed16_vec3;

    #[test]
    fn copies_all_three_fixed16_components() {
        let src = [0x0001_8000i32, -0x0000_8000, 0x7fff_ffff];
        let mut dst = [0i32; 3];

        unsafe { copy_fixed16_vec3(dst.as_mut_ptr(), src.as_ptr()) };

        assert_eq!(dst, src);
    }

    #[test]
    fn preserves_forward_order_for_overlapping_words() {
        let mut words = [10i32, 20, 30, 40];

        unsafe { copy_fixed16_vec3(words.as_mut_ptr().add(1), words.as_ptr()) };

        assert_eq!(words, [10, 10, 10, 10]);
    }
}
