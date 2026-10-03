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

/// `negate_fixed16_vec3` — original: `FUN_082a018c` @ 0x082a018c (36 bytes).
///
/// Negates three Q16.16 component words with wrapping i32 arithmetic, loading
/// all components before any store so both in-place and partial overlap work.
/// Raw words establish 0x082a018c..0x082a01b0; the next independently called
/// function starts with `push {lr}` at 0x082a01b0. Whole-image aligned A32
/// decoding finds two plain inbound BLs (0x08252320 and 0x08252fa8), zero
/// predicated inbound BLs, and zero outgoing BLs. No deliberate behavioral
/// deviations; volatile accesses preserve the stock load/store ordering.
///
/// # Safety
/// `src` must provide three readable aligned i32 words and `dst` three writable
/// aligned i32 words. The ranges may overlap.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.negate_fixed16_vec3")]
pub unsafe extern "C" fn negate_fixed16_vec3(dst: *mut i32, src: *const i32) {
    let x = core::ptr::read_volatile(src);
    let y = core::ptr::read_volatile(src.add(1));
    let z = core::ptr::read_volatile(src.add(2));
    core::ptr::write_volatile(dst, x.wrapping_neg());
    core::ptr::write_volatile(dst.add(1), y.wrapping_neg());
    core::ptr::write_volatile(dst.add(2), z.wrapping_neg());
}

/// `scale_fixed16_vec3` — original: `FUN_0824c6f4` @ 0x0824c6f4 (64 bytes).
///
/// Scales each of three signed Q16.16 words in place by `scale`, retaining
/// bits 16..47 of the signed 64-bit product (round down, wrap on overflow).
/// Raw A32 extent is 0x0824c6f4..0x0824c734, ending in bx lr; the next
/// function begins with ldr r2, [r1]. Whole-image aligned decoding verifies
/// two plain inbound BLs (0x0824c074, 0x0824c224), zero predicated inbound
/// BLs, and zero outgoing BLs. Volatile accesses retain the sequential
/// load/multiply/store order. No deliberate behavioral deviations.
///
/// # Safety
/// `vector` must point to three readable and writable aligned i32 words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.scale_fixed16_vec3")]
pub unsafe extern "C" fn scale_fixed16_vec3(vector: *mut i32, scale: i32) {
    for index in 0..3 {
        let component = core::ptr::read_volatile(vector.add(index));
        let product = (component as i64) * (scale as i64);
        core::ptr::write_volatile(vector.add(index), (product >> 16) as i32);
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_fixed16_vec3, negate_fixed16_vec3, scale_fixed16_vec3};

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

    #[test]
    fn negates_components_and_wraps_minimum() {
        for src in [
            [0, 1, -1],
            [i32::MIN, i32::MAX, -0x0001_8000],
            [0x0000_8000, -0x0000_8000, 0x0001_0000],
        ] {
            let mut dst = [123i32; 5];
            unsafe { negate_fixed16_vec3(dst.as_mut_ptr().add(1), src.as_ptr()) };
            let expected = src.map(|component| (-(component as i64)) as i32);
            assert_eq!(dst, [123, expected[0], expected[1], expected[2], 123]);
        }
    }

    #[test]
    fn snapshots_all_components_before_overlapping_stores() {
        for src_start in 0..=2 {
            for dst_start in 0..=2 {
                let mut words = [i32::MIN, 0x18000, -7, i32::MAX, 42];
                let original = words;
                let mut expected = original;
                for component in 0..3 {
                    expected[dst_start + component] =
                        (-(original[src_start + component] as i64)) as i32;
                }
                unsafe {
                    negate_fixed16_vec3(
                        words.as_mut_ptr().add(dst_start),
                        words.as_ptr().add(src_start),
                    );
                }
                assert_eq!(words, expected, "src={src_start}, dst={dst_start}");
            }
        }
    }

    #[test]
    fn scales_signed_fractional_and_overflowing_components() {
        let values = [
            i32::MIN, i32::MIN + 1, -0x18000, -0x10001, -0x8000, -1,
            0, 1, 0x8000, 0x10000, 0x18000, i32::MAX,
        ];
        for scale in values {
            for x in values {
                let mut words = [123, x, x.wrapping_add(1), x.wrapping_neg(), 456];
                let original = words;
                unsafe { scale_fixed16_vec3(words.as_mut_ptr().add(1), scale) };
                let mut expected = original;
                for index in 1..=3 {
                    // Independent floor division, rather than signed shifting.
                    let product = (original[index] as i128) * (scale as i128);
                    expected[index] = product.div_euclid(65536) as i32;
                }
                assert_eq!(words, expected, "x={x}, scale={scale}");
            }
        }
    }

    #[test]
    fn negative_fraction_rounds_down_and_overflow_wraps() {
        let mut vector = [-1, 1, i32::MIN];
        unsafe { scale_fixed16_vec3(vector.as_mut_ptr(), 0x8000) };
        assert_eq!(vector, [-1, 0, -0x4000_0000]);
        let mut vector = [i32::MAX, i32::MIN, 0x10000];
        unsafe { scale_fixed16_vec3(vector.as_mut_ptr(), 0x20000) };
        assert_eq!(vector, [-2, 0, 0x20000]);
    }
}
