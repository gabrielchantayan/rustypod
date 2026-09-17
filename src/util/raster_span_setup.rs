//! raster_span_setup — original: `FUN_0823b4c8` @ `0x0823b4c8`.
//!
//! **Original:** retailOS 2.0.4. Raw `osos.dec` establishes the true 192-byte
//! extent `0x0823b4c8..0x0823b584`; the aligned word at `0x0823b588` is this
//! function's literal callback address and `0x0823b58c` begins the next
//! independently linked function with `push {r1-r11,lr}`. A whole-image A32
//! branch decode finds four inbound plain `bl` instructions (`0x082409f0`,
//! `0x08240e80`, `0x08241da8`, `0x08242c88`) and no predicated `bl` calls.
//!
//! Copies the source raster's dimensions and format bytes into a 28-byte span
//! descriptor, derives the two backing-store addresses from aligned `(x, y)`
//! coordinates, and installs the stock callback word `0x08a1b5a4`. Formats 4,
//! 5, 6, and 7 select horizontal shifts 2, 1, 1, and 1 respectively; source
//! layout byte 0 selects vertical shift 1 and byte 1 selects 2. Other values
//! deliberately leave the corresponding descriptor halfword unchanged, as the
//! original's predicated stores do.
//!
//! Deliberate deviation: the callback word is retained as a `u32` rather than
//! assigning it a Rust function-pointer type, because its callee identity is
//! not yet established in `names.yaml`.

/// The 28-byte raster span descriptor configured by [`raster_span_setup`].
/// All fields retain their retailOS offsets on both host and target builds.
#[repr(C)]
pub struct RasterSpanDescriptor {
    pub primary_address: u32,
    pub secondary_address: u32,
    pub width: u16,
    pub height: u16,
    pub source_stride: u32,
    pub horizontal_shift: i16,
    pub vertical_shift: i16,
    pub format: i8,
    pub layout: i8,
    pub callback: u32,
}

/// The source raster fields read by [`raster_span_setup`].
#[repr(C)]
pub struct RasterSpanSource {
    _padding_00_63: [u8; 0x64],
    pub format: i8,
    pub layout: i8,
    _padding_66_67: [u8; 2],
    pub primary_base: u32,
    _padding_6c_6f: [u8; 4],
    pub secondary_base: u32,
    _padding_74_93: [u8; 0x20],
    pub stride: u32,
    pub height: u32,
}

#[inline(always)]
fn arm_lsl_register(value: u32, shift: i16) -> u32 {
    match (shift as u32) & 0xff {
        0 => value,
        1..=31 => value << ((shift as u32) & 0xff),
        _ => 0,
    }
}

/// raster_span_setup — original: `FUN_0823b4c8` @ `0x0823b4c8` (192 bytes;
/// 4 plain inbound `bl` calls and 0 predicated inbound `bl` calls).
///
/// Configures `descriptor` for source coordinates `x` and `y`. Arithmetic and
/// register shifts wrap exactly as ARM A32 does. `descriptor` and `source`
/// must point to valid retailOS-layout objects; neither is null-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn raster_span_setup(
    descriptor: *mut RasterSpanDescriptor,
    source: *const RasterSpanSource,
    x: u32,
    y: u32,
) {
    let descriptor = &mut *descriptor;
    let source = &*source;

    descriptor.width = source.stride as u16;
    descriptor.height = source.height as u16;
    descriptor.source_stride = source.stride;

    let x_mod_8 = x & 7;
    let y_mod_8 = y & 7;
    let primary_offset = source.stride.wrapping_mul(x).wrapping_add(y);
    let secondary_offset = (source.stride as u16 as u32)
        .wrapping_mul(x.wrapping_sub(x_mod_8))
        .wrapping_add(y.wrapping_sub(y_mod_8))
        .wrapping_add(x_mod_8 << 3)
        .wrapping_add(y_mod_8);

    descriptor.format = source.format;
    if source.format == 4 {
        descriptor.horizontal_shift = 2;
    } else if matches!(source.format, 5..=7) {
        descriptor.horizontal_shift = 1;
    }

    descriptor.layout = source.layout;
    if source.layout == 0 {
        descriptor.vertical_shift = 1;
    } else if source.layout == 1 {
        descriptor.vertical_shift = 2;
    }

    descriptor.primary_address = source
        .primary_base
        .wrapping_add(arm_lsl_register(primary_offset, descriptor.horizontal_shift));
    descriptor.secondary_address = source
        .secondary_base
        .wrapping_add(arm_lsl_register(secondary_offset, descriptor.vertical_shift));
    descriptor.callback = 0x08a1_b5a4;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(format: i8, layout: i8, stride: u32, height: u32) -> RasterSpanSource {
        RasterSpanSource {
            _padding_00_63: [0; 0x64], format, layout, _padding_66_67: [0; 2],
            primary_base: 0x1000_0000, _padding_6c_6f: [0; 4],
            secondary_base: 0x2000_0000, _padding_74_93: [0; 0x20], stride, height,
        }
    }

    fn descriptor(horizontal_shift: i16, vertical_shift: i16) -> RasterSpanDescriptor {
        RasterSpanDescriptor {
            primary_address: 0, secondary_address: 0, width: 0, height: 0,
            source_stride: 0, horizontal_shift, vertical_shift, format: 0, layout: 0, callback: 0,
        }
    }

    #[test]
    fn configures_aligned_offsets_and_format_shifts() {
        let source = source(4, 1, 0x1_0003, 0x2_0004);
        let mut descriptor = descriptor(-1, -1);
        unsafe { raster_span_setup(&mut descriptor, &source, 10, 13) };
        assert_eq!(descriptor.width, 3);
        assert_eq!(descriptor.height, 4);
        assert_eq!(descriptor.source_stride, 0x1_0003);
        assert_eq!(descriptor.format, 4);
        assert_eq!(descriptor.layout, 1);
        assert_eq!(descriptor.horizontal_shift, 2);
        assert_eq!(descriptor.vertical_shift, 2);
        assert_eq!(descriptor.primary_address, 0x1000_0000u32.wrapping_add(0x1_0003 * 10 + 13 << 2));
        assert_eq!(descriptor.secondary_address, 0x2000_0000u32.wrapping_add(8 * 0x0003 + 8 + 16 + 5 << 2));
        assert_eq!(descriptor.callback, 0x08a1_b5a4);
    }

    #[test]
    fn unmatched_formats_preserve_shift_halfwords_and_arm_large_shift_zeroes_offset() {
        let source = source(-1, 2, u32::MAX, 0xffff_fffe);
        let mut descriptor = descriptor(32, 33);
        unsafe { raster_span_setup(&mut descriptor, &source, u32::MAX, 7) };
        assert_eq!(descriptor.horizontal_shift, 32);
        assert_eq!(descriptor.vertical_shift, 33);
        assert_eq!(descriptor.primary_address, 0x1000_0000);
        assert_eq!(descriptor.secondary_address, 0x2000_0000);
        assert_eq!(descriptor.width, u16::MAX);
        assert_eq!(descriptor.height, 0xfffe);
    }
}
