//! Port of the retailOS packed-color unpacker at `0x080ed43c` — the
//! routine the text/layout drawing code uses to turn a color in any of
//! the firmware's source pixel formats into a 4-byte RGBA8 quad.

/// A format flag the original masks off before dispatching
/// (`bic r1, r1, #0x2000`): formats arriving with bit 13 set behave
/// exactly like the same format without it.
const IGNORED_FORMAT_FLAG: u32 = 0x2000;

/// Magic multiplier for the gray4 path's divide-by-15
/// (`2^35 / 15` rounded up); the original multiplies by this with
/// `umull` and keeps `product >> 35`.
const GRAY4_DIV15_MAGIC: u64 = 0x88888889;

/// Dither patterns format 2 recognises: every 2-bit group equal to
/// 0b01 / 0b10 respectively. 0b11 (or anything unrecognised) takes the
/// foreground constant.
const DITHER_PATTERN_01: u32 = 0x55555555;
const DITHER_PATTERN_10: u32 = 0xaaaaaaaa;

/// Canned 4-byte colors for the mono/dither formats. The original does
/// not keep these in a table of its own — its literal pool holds four
/// absolute pointers that land *inside the localized clock-city string
/// table* (`\0Clock_String_Katmandu\0..\0Clock_String_Mogadishu\0`), and
/// it byte-copies 4 bytes from each. The bytes below are captured by
/// value from those addresses (osos.dec offsets = address - 0x08000000):
///
/// - `PATTERN_BG` @ `0x089cc8c0` — `00 43 6c 6f` (`\0Clo`)
/// - `PATTERN_MID_01` @ `0x089cc8c4` — `63 6b 5f 53` (`ck_S`)
/// - `PATTERN_MID_10` @ `0x089cc8cc` — `67 5f 4d 6f` (`g_Mo`)
/// - `PATTERN_FG` @ `0x089cc8d0` — `67 61 64 69` (`gadi`, also the
///   fallback for every unrecognised format)
static PATTERN_BG: [u8; 4] = [0x00, 0x43, 0x6c, 0x6f];
static PATTERN_MID_01: [u8; 4] = [0x63, 0x6b, 0x5f, 0x53];
static PATTERN_MID_10: [u8; 4] = [0x67, 0x5f, 0x4d, 0x6f];
static PATTERN_FG: [u8; 4] = [0x67, 0x61, 0x64, 0x69];

/// Nibble-expansion table for the RGBA4444 path. The original reads 16
/// bytes at the absolute address `0x083f85a8`, which sits in the middle
/// of a (u16 counter, u16 value) pair table (`01 02 a2 21 02 02 a4 21
/// ...`) — not a purpose-built nibble table either. Captured by value.
static NIBBLE_TABLE: [u8; 16] = [
    0x05, 0x02, 0xaa, 0x21, //
    0x06, 0x02, 0xac, 0x21, //
    0x07, 0x02, 0xae, 0x21, //
    0x08, 0x02, 0xb0, 0x21,
];

/// Byte-copies one of the canned colors, volatile so LLVM neither
/// merges the stores nor rewrites the copy into a libc call (the
/// original emits four `ldrb`/`strb` pairs per constant).
#[inline(always)]
unsafe fn write_canned(out: *mut u8, canned: &'static [u8; 4]) {
    for i in 0..4 {
        out.add(i)
            .write_volatile(canned.as_ptr().add(i).read_volatile());
    }
}

/// color_to_rgba8 — original: `FUN_080ed43c` @ 0x080ed43c (652 bytes,
/// 37 `bl` call sites, a pure leaf).
///
/// Unpacks `color` from the source pixel format selected by `format`
/// into four bytes at `out`, in R, G, B, A order. `format` is first
/// masked with `0xffffdfff` (bit 13 is ignored), then dispatched:
///
/// - `0x1` (mono): nonzero `color` writes the canned foreground, zero
///   the canned background.
/// - `0x2` (2bpp dither): `0x00000000` -> background, `0x55555555` ->
///   mid-01, `0xaaaaaaaa` -> mid-10, anything else -> foreground.
/// - `0x4` (gray4, inverted): `gray = ((0xf - (color & 0xf)) * 0xff) /
///   15`, computed as a `umull` by `0x88888889` kept at `>> 35` (exact
///   `(15 - nibble) * 17`, i.e. nibble replication); written to R=G=B,
///   alpha `0xff`.
/// - `0x8` (gray8, inverted): `0xff - (color & 0xff)` to R=G=B, alpha
///   `0xff`.
/// - `0x565` (RGB565): 5/6-bit fields expanded to 8 bits by
///   shift-or-replication, alpha `0xff`.
/// - `0x555` (RGB555): same with a 5-bit green channel.
/// - `0x1888` (ARGB8888): byte reorder — out is R, G, B, A from the
///   `0xAARRGGBB` input.
/// - `0x1444` (RGBA4444): each nibble expanded through the 16-byte
///   [`NIBBLE_TABLE`].
/// - anything else: the canned foreground.
///
/// Deviations: the four canned colors and the nibble table are embedded
/// by value; the original loads them through absolute pointers that
/// alias unrelated rodata (the clock-city string table and a u16-pair
/// table — see the constants above). Behavior is identical for every
/// input because those regions are read-only in the image.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn color_to_rgba8(color: u32, format: u32, out: *mut u8) {
    match format & !IGNORED_FORMAT_FLAG {
        0x1 => {
            if color != 0 {
                write_canned(out, &PATTERN_FG);
            } else {
                write_canned(out, &PATTERN_BG);
            }
        }
        0x2 => {
            if color == 0 {
                write_canned(out, &PATTERN_BG);
            } else if color == DITHER_PATTERN_01 {
                write_canned(out, &PATTERN_MID_01);
            } else if color == DITHER_PATTERN_10 {
                write_canned(out, &PATTERN_MID_10);
            } else {
                write_canned(out, &PATTERN_FG);
            }
        }
        0x4 => {
            let level = 0xf - (color & 0xf);
            let gray = ((level as u64 * 0xff * GRAY4_DIV15_MAGIC) >> 35) as u8;
            out.add(0).write_volatile(gray);
            out.add(1).write_volatile(gray);
            out.add(2).write_volatile(gray);
            out.add(3).write_volatile(0xff);
        }
        0x8 => {
            let gray = 0xffu8.wrapping_sub(color as u8);
            out.add(0).write_volatile(gray);
            out.add(1).write_volatile(gray);
            out.add(2).write_volatile(gray);
            out.add(3).write_volatile(0xff);
        }
        0x565 => {
            let red = color & 0xf800;
            let green = color & 0x7e0;
            let blue = color & 0x1f;
            out.add(0)
                .write_volatile(((red >> 8) | (red >> 0xd)) as u8);
            out.add(1)
                .write_volatile(((green >> 3) | (green >> 9)) as u8);
            out.add(2)
                .write_volatile(((blue << 3) | (blue >> 2)) as u8);
            out.add(3).write_volatile(0xff);
        }
        0x555 => {
            let red = color & 0x7c00;
            let green = color & 0x3e0;
            let blue = color & 0x1f;
            out.add(0)
                .write_volatile(((red >> 7) | (red >> 0xc)) as u8);
            out.add(1)
                .write_volatile(((green >> 2) | (green >> 7)) as u8);
            out.add(2)
                .write_volatile(((blue << 3) | (blue >> 2)) as u8);
            out.add(3).write_volatile(0xff);
        }
        0x1888 => {
            out.add(0).write_volatile((color >> 0x10) as u8);
            out.add(1).write_volatile((color >> 8) as u8);
            out.add(2).write_volatile(color as u8);
            out.add(3).write_volatile((color >> 0x18) as u8);
        }
        0x1444 => {
            out.add(0)
                .write_volatile(NIBBLE_TABLE[((color & 0xf00) >> 8) as usize]);
            out.add(1)
                .write_volatile(NIBBLE_TABLE[((color & 0xf0) >> 4) as usize]);
            out.add(2)
                .write_volatile(NIBBLE_TABLE[(color & 0xf) as usize]);
            out.add(3)
                .write_volatile(NIBBLE_TABLE[((color & 0xf000) >> 0xc) as usize]);
        }
        _ => write_canned(out, &PATTERN_FG),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference constants, spelled as literals so the tests fail if the
    /// module's captured values drift from the image bytes.
    const BG: [u8; 4] = [0x00, 0x43, 0x6c, 0x6f];
    const MID_01: [u8; 4] = [0x63, 0x6b, 0x5f, 0x53];
    const MID_10: [u8; 4] = [0x67, 0x5f, 0x4d, 0x6f];
    const FG: [u8; 4] = [0x67, 0x61, 0x64, 0x69];
    const TABLE: [u8; 16] = [
        0x05, 0x02, 0xaa, 0x21, 0x06, 0x02, 0xac, 0x21, //
        0x07, 0x02, 0xae, 0x21, 0x08, 0x02, 0xb0, 0x21,
    ];

    /// Independent reference implementation, written straight from the
    /// Ghidra decompilation of the original.
    fn reference(color: u32, format: u32) -> [u8; 4] {
        match format & 0xffff_dfff {
            1 => {
                if color != 0 {
                    FG
                } else {
                    BG
                }
            }
            2 => {
                if color == 0 {
                    BG
                } else if color == 0x5555_5555 {
                    MID_01
                } else if color == 0xaaaa_aaaa {
                    MID_10
                } else {
                    FG
                }
            }
            4 => {
                let g = ((((0xf - (color & 0xf)) as u64) * 0xff * 0x8888_8889) >> 0x23) as u8;
                [g, g, g, 0xff]
            }
            8 => {
                let g = (0xffu32.wrapping_sub(color & 0xff)) as u8;
                [g, g, g, 0xff]
            }
            0x565 => [
                (((color & 0xf800) >> 8) | ((color & 0xf800) >> 0xd)) as u8,
                (((color & 0x7e0) >> 3) | ((color & 0x7e0) >> 9)) as u8,
                (((color & 0x1f) << 3) | ((color & 0x1f) >> 2)) as u8,
                0xff,
            ],
            0x555 => [
                (((color & 0x7c00) >> 7) | ((color & 0x7c00) >> 0xc)) as u8,
                (((color & 0x3e0) >> 2) | ((color & 0x3e0) >> 7)) as u8,
                (((color & 0x1f) << 3) | ((color & 0x1f) >> 2)) as u8,
                0xff,
            ],
            0x1888 => [
                (color >> 0x10) as u8,
                (color >> 8) as u8,
                color as u8,
                (color >> 0x18) as u8,
            ],
            0x1444 => [
                TABLE[((color & 0xf00) >> 8) as usize],
                TABLE[((color & 0xf0) >> 4) as usize],
                TABLE[(color & 0xf) as usize],
                TABLE[((color & 0xf000) >> 0xc) as usize],
            ],
            _ => FG,
        }
    }

    fn convert(color: u32, format: u32) -> [u8; 4] {
        let mut out = [0xaa; 4]; // pre-dirtied: every path writes all 4 bytes
        unsafe { color_to_rgba8(color, format, out.as_mut_ptr()) };
        out
    }

    /// Colors that exercise extremes of every field the formats read.
    fn color_corpus() -> [u32; 18] {
        [
            0x0000_0000,
            0x0000_0001,
            0xffff_ffff,
            0x5555_5555,
            0xaaaa_aaaa,
            0x5a5a_5a5a,
            0x0000_000f,
            0x0000_00f0,
            0x1234_5678,
            0x87ff_ffff,
            0x0000_f800,
            0x0000_07e0,
            0x0000_001f,
            0x0000_7c00,
            0x0000_03e0,
            0xdead_beef,
            0x00ff_ff00,
            0x8080_8080,
        ]
    }

    /// Every masked dispatch value, plus unrecognised ones that must
    /// take the fallback.
    fn format_corpus() -> [u32; 13] {
        [
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x555, 0x565, 0x1444,
        ]
    }

    #[test]
    fn mono_format_selects_foreground_or_background() {
        assert_eq!(convert(0, 1), BG);
        for color in [1, 0xff, 0xffff_ffff, 0x8000_0000] {
            assert_eq!(convert(color, 1), FG, "color={color:#010x}");
        }
    }

    #[test]
    fn dither_format_dispatches_on_exact_patterns() {
        assert_eq!(convert(0, 2), BG);
        assert_eq!(convert(0x5555_5555, 2), MID_01);
        assert_eq!(convert(0xaaaa_aaaa, 2), MID_10);
        // Exact matches only: neighbours and mixed patterns fall through
        // to the foreground constant.
        for color in [1, 0x5555_5554, 0x5555_5556, 0x5a5a_5a5a, 0xffff_ffff] {
            assert_eq!(convert(color, 2), FG, "color={color:#010x}");
        }
    }

    #[test]
    fn gray4_is_the_inverted_nibble_replicated_to_a_byte() {
        for nibble in 0..16u32 {
            let want = ((0xf - nibble) * 0x11) as u8;
            assert_eq!(convert(nibble, 4), [want, want, want, 0xff]);
        }
        // Only the low nibble is read.
        assert_eq!(convert(0xffff_fff0, 4), [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(convert(0xdead_beef, 4), [0, 0, 0, 0xff]);
    }

    #[test]
    fn gray8_inverts_the_low_byte() {
        for byte in [0u32, 1, 0x7f, 0x80, 0xfe, 0xff] {
            let want = (0xff - byte) as u8;
            assert_eq!(convert(byte, 8), [want, want, want, 0xff]);
        }
        // Only the low byte is read.
        assert_eq!(convert(0xffff_ff00, 8), [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(convert(0x1234_56ff, 8), [0, 0, 0, 0xff]);
    }

    #[test]
    fn rgb565_expands_channels_by_shift_or_replication() {
        assert_eq!(convert(0xf800, 0x565), [0xff, 0x00, 0x00, 0xff]);
        assert_eq!(convert(0x07e0, 0x565), [0x00, 0xff, 0x00, 0xff]);
        assert_eq!(convert(0x001f, 0x565), [0x00, 0x00, 0xff, 0xff]);
        assert_eq!(convert(0x0000, 0x565), [0x00, 0x00, 0x00, 0xff]);
        // Mid-range channel: top bits replicated into the low bits.
        assert_eq!(convert(0x2800, 0x565), [(5 << 3) | (5 >> 2), 0, 0, 0xff]);
        assert_eq!(convert(0x0140, 0x565), [0, (10 << 2) | (10 >> 4), 0, 0xff]);
        // Bits above bit 15 are ignored.
        assert_eq!(convert(0xffff_0000 | 0xf800, 0x565), [0xff, 0, 0, 0xff]);
    }

    #[test]
    fn rgb555_expands_a_five_bit_green() {
        assert_eq!(convert(0x7c00, 0x555), [0xff, 0x00, 0x00, 0xff]);
        assert_eq!(convert(0x03e0, 0x555), [0x00, 0xff, 0x00, 0xff]);
        assert_eq!(convert(0x001f, 0x555), [0x00, 0x00, 0xff, 0xff]);
        assert_eq!(convert(0x0000, 0x555), [0x00, 0x00, 0x00, 0xff]);
        // 565 and 555 disagree on the same bits, as they must: 0x07e0
        // is full green plus red's LSB in 555.
        assert_eq!(convert(0x07e0, 0x555), [0x08, 0xff, 0x00, 0xff]);
    }

    #[test]
    fn argb8888_is_a_byte_reorder_to_rgba() {
        assert_eq!(convert(0x1122_3344, 0x1888), [0x22, 0x33, 0x44, 0x11]);
        assert_eq!(convert(0x0000_0000, 0x1888), [0, 0, 0, 0]);
        assert_eq!(convert(0xffff_ffff, 0x1888), [0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn rgba4444_looks_up_each_nibble_in_the_table() {
        for nibble in 0..16u32 {
            let t = TABLE[nibble as usize];
            // The same nibble in all four positions.
            let packed = nibble | (nibble << 4) | (nibble << 8) | (nibble << 12);
            assert_eq!(convert(packed, 0x1444), [t, t, t, t]);
        }
        // Position order is R, G, B, A from low nibbles upward.
        assert_eq!(
            convert(0x1234, 0x1444),
            [TABLE[2], TABLE[3], TABLE[4], TABLE[1]]
        );
        // Bits above bit 15 are ignored.
        assert_eq!(convert(0xffff_0000 | 0x0001, 0x1444), convert(0x0001, 0x1444));
    }

    #[test]
    fn unrecognised_formats_fall_back_to_the_foreground() {
        for format in [0u32, 3, 5, 6, 7, 9, 0x100, 0x9999, 0xffff_dfff] {
            for color in [0, 1, 0x5555_5555, 0xffff_ffff] {
                assert_eq!(convert(color, format), FG, "format={format:#06x}");
            }
        }
    }

    #[test]
    fn bit_13_of_the_format_is_ignored() {
        for format in [1u32, 2, 4, 8, 0x555, 0x565, 0x1444, 0x1888, 0x9999] {
            for color in color_corpus() {
                assert_eq!(
                    convert(color, format | 0x2000),
                    convert(color, format),
                    "color={color:#010x} format={format:#06x}"
                );
            }
        }
        // The masked bit must be *cleared*, not the whole word masked
        // down: 0x3888 masks to 0x1888, and 0x10001 does not become 1.
        assert_eq!(convert(0x1122_3344, 0x3888), [0x22, 0x33, 0x44, 0x11]);
        assert_eq!(convert(1, 0x1_0001), FG);
    }

    #[test]
    fn matches_reference_over_the_corpus() {
        for &format in format_corpus().iter().chain(&[0x1888, 0x2001, 0x2565]) {
            for color in color_corpus() {
                assert_eq!(
                    convert(color, format),
                    reference(color, format),
                    "color={color:#010x} format={format:#06x}"
                );
            }
        }
    }

    #[test]
    fn matches_reference_over_exhaustive_gray_and_nibble_inputs() {
        for color in 0..=0xfffu32 {
            assert_eq!(convert(color, 4), reference(color, 4), "gray4 {color:#05x}");
            assert_eq!(convert(color, 8), reference(color, 8), "gray8 {color:#05x}");
            assert_eq!(convert(color, 0x1444), reference(color, 0x1444));
        }
        // Exhaustive 16-bit inputs for the 16-bit-per-pixel formats.
        for color in 0..=0xffffu32 {
            assert_eq!(convert(color, 0x565), reference(color, 0x565));
            assert_eq!(convert(color, 0x555), reference(color, 0x555));
        }
    }
}
