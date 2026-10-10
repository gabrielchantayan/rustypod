/// Pixel-format storage depth — `FUN_080a63f8` @ **0x080a63f8**.
///
/// True extent: 196 bytes through 0x080a64bb (188 instruction bytes and
/// two literal words); the next function starts at 0x080a64bc. Raw ARM-word
/// decoding verifies two incoming plain BLs (0x0810e73c, 0x0810e864), no
/// incoming predicated BLs, and no outgoing plain or predicated BLs.
///
/// Clears format flag 0x2000, then maps recognized pixel-format codes to
/// 1, 2, 4, 8, 16 or 32 bits per pixel. Unknown codes return zero. Callers
/// use this depth to calculate four-byte-aligned image row strides.
/// Deliberate deviation: a match replaces the signed comparison tree; exact
/// code equality preserves its behavior for all u32 inputs. No memory access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn pixel_format_bits_per_pixel(format: u32) -> u32 {
    match format & !0x2000 {
        1 => 1,
        2 => 2,
        4 => 4,
        8 | 0x64 => 8,
        0x65 | 0x555 | 0x565 | 0x1444 | 0xc420 | 0xc422 => 16,
        0x1888 | 0xd444 => 32,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::pixel_format_bits_per_pixel;

    // Independent enumerated firmware code/depth pairs, including aliases.
    const FORMATS: [(u32, u32); 13] = [
        (1, 1), (2, 2), (4, 4), (8, 8), (0x64, 8), (0x65, 16),
        (0x555, 16), (0x565, 16), (0x1444, 16), (0x1888, 32),
        (0xc420, 16), (0xc422, 16), (0xd444, 32),
    ];

    #[test]
    fn all_low_word_codes_and_flag_aliases() {
        for format in 0..=0xffff {
            let expected = FORMATS.iter()
                .find(|&&(code, _)| format == code || format == code | 0x2000)
                .map_or(0, |&(_, depth)| depth);
            assert_eq!(pixel_format_bits_per_pixel(format), expected, "format={format:#x}");
        }
    }

    #[test]
    fn other_flags_and_signed_values_are_not_truncated() {
        for &(format, _) in &FORMATS {
            for extra in [0x10000, 0x4000_0000, 0x8000_0000, 0xffff_0000] {
                assert_eq!(pixel_format_bits_per_pixel(format | extra), 0);
                assert_eq!(pixel_format_bits_per_pixel(format | extra | 0x2000), 0);
            }
        }
        for format in [0, 0x2000, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
            assert_eq!(pixel_format_bits_per_pixel(format), 0);
        }
    }
}
