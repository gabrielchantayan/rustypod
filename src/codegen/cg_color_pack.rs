//! Pixel-component packing used by the Vincent pipeline generator.

/// `cg_pack_color` — original: `FUN_0823a5d8` @ 0x0823a5d8.
///
/// The verified extent is 212 bytes (53 ARM instruction words), from the
/// initial `cmp r0,#4` through `bx lr` at 0x0823a6a8; the next function opens
/// with `push {r3-r9,lr}` at 0x0823a6ac. The leaf has no BL instructions.
/// Whole-image decoding finds three direct callers, all unconditional `bl`
/// (0x0823f8c4, 0x0823f93c, and 0x0823f960), and no predicated BL callers.
///
/// Packs four component bytes according to the pixel-format selector: 4 is
/// big-endian RGBA8888, 5 is RGB565, 6 is RGBA4444, and 7 is RGBA5551. Any
/// other selector returns zero without reading `components`, matching the
/// conditional ARM exits.
///
/// # Deliberate deviations
///
/// The retail body orders several loads to suit register allocation. This
/// port reads the same bytes by their semantic component positions; it has no
/// observable difference because each path loads only immutable input bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_pack_color(pixel_format: i32, components: *const u8) -> u32 {
    match pixel_format {
        4 => unsafe {
            (components.read() as u32) << 24
                | (components.add(1).read() as u32) << 16
                | (components.add(2).read() as u32) << 8
                | components.add(3).read() as u32
        },
        5 => unsafe {
            (components.add(2).read() as u32 >> 3)
                | ((components.add(1).read() as u32 & 0xfc) << 3)
                | ((components.read() as u32 & 0xf8) << 8)
        },
        6 => unsafe {
            ((components.read() as u32 & 0xf0) << 8)
                | ((components.add(1).read() as u32 & 0xf0) << 4)
                | (components.add(2).read() as u32 & 0xf0)
                | (components.add(3).read() as u32 >> 4)
        },
        7 => unsafe {
            ((components.add(2).read() as u32 & 0xf8) >> 2)
                | ((components.add(1).read() as u32 & 0xf8) << 3)
                | ((components.read() as u32 & 0xf8) << 8)
                | (components.add(3).read() as u32 >> 7)
        },
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::cg_pack_color;

    fn reference_pack(pixel_format: i32, c: [u8; 4]) -> u32 {
        match pixel_format {
            4 => u32::from_be_bytes(c),
            5 => ((c[0] as u32 >> 3) << 11) | ((c[1] as u32 >> 2) << 5) | (c[2] as u32 >> 3),
            6 => ((c[0] as u32 >> 4) << 12) | ((c[1] as u32 >> 4) << 8)
                | ((c[2] as u32 >> 4) << 4) | (c[3] as u32 >> 4),
            7 => ((c[0] as u32 >> 3) << 11) | ((c[1] as u32 >> 3) << 6)
                | ((c[2] as u32 >> 3) << 1) | (c[3] as u32 >> 7),
            _ => 0,
        }
    }

    #[test]
    fn packs_every_supported_format_and_discards_low_bits() {
        for components in [[0x12, 0x34, 0x56, 0x78], [0xff, 0x03, 0xfc, 0x8f], [0, 0, 0, 0]] {
            for pixel_format in 4..=7 {
                assert_eq!(
                    unsafe { cg_pack_color(pixel_format, components.as_ptr()) },
                    reference_pack(pixel_format, components),
                    "format {pixel_format}, components {components:02x?}",
                );
            }
        }
    }

    #[test]
    fn rejects_unsupported_formats_without_reading_components() {
        for pixel_format in [-1, 0, 3, 8, i32::MAX] {
            assert_eq!(unsafe { cg_pack_color(pixel_format, core::ptr::null()) }, 0);
        }
    }
}
