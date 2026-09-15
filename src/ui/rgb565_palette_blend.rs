//! `rgb565_palette_blend` — original: `FUN_0807fe3c` @ `0x0807fe3c`
//! (192 bytes, `0x0807fe3c..0x0807fefc`; the next separately linked function
//! begins at `0x0807fefc`). Raw ARM decoding finds **five plain,
//! unconditional `bl` call sites** and **zero predicated `bl` call sites**.
//!
//! Reads an 8-bit palette index, selects its Q0.8 blend weight from a u16
//! lookup table, and transforms the destination RGB565 colour before blending
//! it toward the supplied RGB565 target. The transform also receives the
//! resulting RGB565 colour. Weight zero preserves the destination without
//! invoking the transform; weight `0x100` transforms and replaces it with the
//! target. Intermediate weights interpolate packed 5/6/5 fields independently,
//! with signed division rounded toward zero.
//!
//! # Deliberate deviations
//!
//! None.

/// Transforms an RGB565 colour before or after palette interpolation.
pub type Rgb565Transform = unsafe extern "C" fn(u16) -> u16;

/// Blends a palette-selected RGB565 target into a transformed destination.
///
/// # Safety
///
/// `palette_index`, `opacity_table`, `target`, and `destination` must be valid
/// for the respective byte, u16, u16, and u16 accesses. `transform` must be a
/// valid retailOS-compatible function pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb565_palette_blend(
    palette_index: *const u8,
    opacity_table: *const u16,
    target: *const u16,
    transform: Rgb565Transform,
    destination: *mut u16,
) {
    let weight = i32::from(*opacity_table.add(usize::from(*palette_index)));
    if weight == 0 {
        return;
    }

    if weight == 0x100 {
        *destination = transform(*target);
        return;
    }

    let source = transform(*destination);
    let target = *target;
    let red = ((i32::from(target & 0xf800) - i32::from(source & 0xf800)) * weight) / 0x100;
    let green = ((i32::from(target & 0x07e0) - i32::from(source & 0x07e0)) * weight) / 0x100;
    let blue = ((i32::from(target & 0x001f) - i32::from(source & 0x001f)) * weight) / 0x100;

    *destination = transform(
        ((i32::from(source & 0xf800) + red) as u16 & 0xf800)
            | ((i32::from(source & 0x07e0) + green) as u16 & 0x07e0)
            | ((i32::from(source & 0x001f) + blue) as u16 & 0x001f),
    );
}

#[cfg(test)]
mod tests {
    use super::rgb565_palette_blend;

    unsafe extern "C" fn identity(color: u16) -> u16 {
        color
    }

    unsafe extern "C" fn invert(color: u16) -> u16 {
        !color
    }

    #[test]
    fn zero_weight_preserves_destination_without_transforming() {
        let opacity = [0, 0x100];
        let index = 0;
        let target = 0xffff;
        let mut destination = 0x1234;

        unsafe {
            rgb565_palette_blend(
                &index,
                opacity.as_ptr(),
                &target,
                invert,
                &mut destination,
            );
        }

        assert_eq!(destination, 0x1234);
    }

    #[test]
    fn full_weight_transforms_target_without_reading_destination() {
        let opacity = [0, 0x100];
        let index = 1;
        let target = 0x1234;
        let mut destination = 0xabcd;

        unsafe {
            rgb565_palette_blend(
                &index,
                opacity.as_ptr(),
                &target,
                invert,
                &mut destination,
            );
        }

        assert_eq!(destination, !target);
    }

    #[test]
    fn half_weight_blends_rgb565_fields_independently() {
        let opacity = [0x80];
        let index = 0;
        let target = 0xffff;
        let mut destination = 0;

        unsafe {
            rgb565_palette_blend(
                &index,
                opacity.as_ptr(),
                &target,
                identity,
                &mut destination,
            );
        }

        assert_eq!(destination, 0x7bef);
    }

    #[test]
    fn signed_component_delta_rounds_toward_zero() {
        let opacity = [0x80];
        let index = 0;
        let target = 0;
        let mut destination = 0xffff;

        unsafe {
            rgb565_palette_blend(
                &index,
                opacity.as_ptr(),
                &target,
                identity,
                &mut destination,
            );
        }

        assert_eq!(destination, 0x7bf0);
    }
}
