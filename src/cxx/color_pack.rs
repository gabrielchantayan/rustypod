//! `color_pack_for_format` — original: `FUN_08272018` @ 0x08272018
//! (120 bytes; **10 unconditional `bl` call sites**, no predicated or tail
//! branches, binary-scanned by decoding every ARM B/BL word in `osos.dec`).
//!
//! Packs RGBA8 components into the 16-bit pixel representation selected by
//! `format`. The raw body starts with `push {r4,r5,lr}` at 0x08272018 and ends
//! with `pop {r4,r5,pc}` at 0x0827208c; 0x08272090 starts the distinct RGB565
//! leaf, so Ghidra's 120-byte extent is exact and has no literal pool.
//!
//! The exact format values `0x0565` and `0x2565` select RGB565;
//! `0x1444` selects RGBA4444; every other value, including `0x0555`, selects
//! RGB555. The original compares full `u32` values rather than masking flags.
//! Components are supplied as `r1`, `r2`, `r3`, and the fifth stack argument
//! in R/G/B/A order.
//!
//! # Deliberate deviations
//!
//! The ARM ABI returns the packed 16-bit value in `r0`; this port represents
//! that unchanged register value as `u32`. It adds no null, range, or format
//! validation because the original is a pure bitwise leaf.

const FORMAT_RGB565: u32 = 0x0565;
const FORMAT_RGB565_ALTERNATE: u32 = 0x2565;
const FORMAT_RGBA4444: u32 = 0x1444;

/// Packs 8-bit R/G/B/A components into the pixel format selected by `format`.
///
/// `0x0565` and `0x2565` yield RGB565; `0x1444` yields RGBA4444 in the
/// firmware's A-R-G-B nibble order; every other format yields RGB555.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn color_pack_for_format(
    format: u32,
    red: u32,
    green: u32,
    blue: u32,
    alpha: u32,
) -> u32 {
    match format {
        FORMAT_RGB565 | FORMAT_RGB565_ALTERNATE => {
            ((red & 0xf8) << 8) | ((green & 0xfc) << 3) | ((blue & 0xf8) >> 3)
        }
        FORMAT_RGBA4444 => {
            ((alpha & 0xf0) << 8)
                | ((red & 0xf0) << 4)
                | (green & 0xf0)
                | ((blue & 0xf0) >> 4)
        }
        _ => ((red & 0xf8) << 7) | ((green & 0xf8) << 2) | ((blue & 0xf8) >> 3),
    }
}

#[cfg(test)]
mod tests {
    use super::color_pack_for_format;

    #[test]
    fn packs_rgb565_and_its_alternate_tag() {
        let expected = 0xf81f;
        assert_eq!(color_pack_for_format(0x0565, 0xff, 0x00, 0xff, 0x12), expected);
        assert_eq!(color_pack_for_format(0x2565, 0xff, 0x00, 0xff, 0xed), expected);
        assert_eq!(color_pack_for_format(0x0565, 0xfa, 0xbf, 0x0f, 0x00), 0xfde1);
    }

    #[test]
    fn packs_all_four_rgba4444_components() {
        assert_eq!(color_pack_for_format(0x1444, 0xab, 0xcd, 0xef, 0x12), 0x1ace);
        assert_eq!(color_pack_for_format(0x1444, 0x0f, 0xf0, 0x9a, 0xb3), 0xb0f9);
    }

    #[test]
    fn all_other_full_width_tags_select_rgb555() {
        assert_eq!(color_pack_for_format(0x0555, 0xff, 0xff, 0xff, 0xff), 0x7fff);
        assert_eq!(color_pack_for_format(0x0000_0565, 0x12, 0x34, 0x56, 0x78), 0x11aa);
        assert_eq!(color_pack_for_format(0x0001_0565, 0xff, 0xff, 0xff, 0xff), 0x7fff);
        assert_eq!(color_pack_for_format(0xffff_1444, 0xff, 0xff, 0xff, 0xff), 0x7fff);
    }
}
