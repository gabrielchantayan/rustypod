//! `rgb565_opacity_blend` — original: `FUN_080966f4` @ `0x080966f4`
//! (184 bytes, `0x080966f4..0x080967ac`; the next separately linked function
//! begins at `0x080967ac`). Raw ARM decoding finds three unconditional `blx`
//! callback invocations and zero `bl` or predicated-call instructions in its
//! body.
//!
//! Applies an 8-bit opacity to an RGB565 target and a transformed destination.
//! Zero opacity preserves the destination without invoking the transform.
//! Other values interpolate packed 5/6/5 fields independently, with signed
//! division rounded toward zero, then transform the result. The ARM contains
//! a `cmp r4,#0x100` fast path, but its preceding `ldrb r4,[r0]` makes that
//! condition unreachable.
//!
//! # Deliberate deviations
//!
//! None.

/// Transforms an RGB565 colour before or after opacity interpolation.
pub type Rgb565Transform = unsafe extern "C" fn(u16) -> u16;

/// Blends an RGB565 target into a transformed destination using Q0.8 opacity.
///
/// # Safety
///
/// `opacity`, `target`, and `destination` must be valid for their respective
/// byte, u16, and u16 accesses. `transform` must be a valid
/// retailOS-compatible function pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb565_opacity_blend(
    opacity: *const u8,
    target: *const u16,
    transform: Rgb565Transform,
    destination: *mut u16,
) {
    let opacity = i32::from(*opacity);
    if opacity == 0 {
        return;
    }


    let source = transform(*destination);
    let target = *target;
    let red = ((i32::from(target & 0xf800) - i32::from(source & 0xf800)) * opacity) / 0x100;
    let green = ((i32::from(target & 0x07e0) - i32::from(source & 0x07e0)) * opacity) / 0x100;
    let blue = ((i32::from(target & 0x001f) - i32::from(source & 0x001f)) * opacity) / 0x100;

    *destination = transform(
        ((i32::from(source & 0xf800) + red) as u16 & 0xf800)
            | ((i32::from(source & 0x07e0) + green) as u16 & 0x07e0)
            | ((i32::from(source & 0x001f) + blue) as u16 & 0x001f),
    );
}

#[cfg(test)]
mod tests {
    use super::rgb565_opacity_blend;

    unsafe extern "C" fn identity(color: u16) -> u16 {
        color
    }

    unsafe extern "C" fn invert(color: u16) -> u16 {
        !color
    }

    #[test]
    fn zero_opacity_preserves_destination_without_transforming() {
        let opacity = 0;
        let target = 0xffff;
        let mut destination = 0x1234;

        unsafe { rgb565_opacity_blend(&opacity, &target, invert, &mut destination) };

        assert_eq!(destination, 0x1234);
    }

    #[test]
    fn intermediate_opacity_blends_rgb565_fields_independently() {
        let opacity = 0x80;
        let target = 0xffff;
        let mut destination = 0;

        unsafe { rgb565_opacity_blend(&opacity, &target, identity, &mut destination) };

        assert_eq!(destination, 0x7bef);
    }

    #[test]
    fn negative_component_delta_rounds_toward_zero() {
        let opacity = 0x80;
        let target = 0;
        let mut destination = 0xffff;

        unsafe { rgb565_opacity_blend(&opacity, &target, identity, &mut destination) };

        assert_eq!(destination, 0x7bf0);
    }
}
