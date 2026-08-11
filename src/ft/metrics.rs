//! FreeType glyph-metric helpers from `ftobjs.c`.

use crate::ft::types::FtGlyphMetrics;

/// FreeType `ft_synthesize_vertical_metrics` — original: `FUN_082cfe0c`
/// @ 0x082cfe0c (76 bytes).
///
/// Synthesizes the vertical extent of a glyph from its horizontal metrics.
/// A zero `advance` derives the historical FreeType heuristic `height * 12 /
/// 10`, with the retail ARM's wrapping 32-bit multiply.  It then writes only
/// `vert_bearing_x`, `vert_bearing_y`, and `vert_advance`; the five horizontal
/// fields stay untouched.  Signed halves use truncation toward zero, exactly
/// as the ARM `add sign-bit; asr #1` sequences do.
///
/// This is FreeType 2.3-era `ftobjs.c`'s
/// `ft_synthesize_vertical_metrics`, confirmed by the direct glyph-loader
/// callers and the eight-word `FT_Glyph_Metrics` layout.
///
/// # Safety
///
/// `metrics` must be a valid, writable `FtGlyphMetrics` pointer.  The retail
/// routine has no null guard.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_synthesize_vertical_metrics(
    metrics: *mut FtGlyphMetrics,
    mut advance: i32,
) {
    let metrics = unsafe { &mut *metrics };
    let height = metrics.height;

    if advance == 0 {
        advance = height.wrapping_mul(12) / 10;
    }

    metrics.vert_bearing_x = -(metrics.width / 2);
    metrics.vert_bearing_y = advance.wrapping_sub(height) / 2;
    metrics.vert_advance = advance;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(width: i32, height: i32) -> FtGlyphMetrics {
        FtGlyphMetrics {
            width,
            height,
            hori_bearing_x: 0x1111_1111,
            hori_bearing_y: 0x2222_2222,
            hori_advance: 0x3333_3333,
            vert_bearing_x: 0x4444_4444,
            vert_bearing_y: 0x5555_5555,
            vert_advance: 0x6666_6666,
        }
    }

    #[test]
    fn supplied_advance_updates_only_the_vertical_extent() {
        let mut actual = metrics(19, -7);
        unsafe { ft_synthesize_vertical_metrics(&mut actual, 25) };

        assert_eq!(actual.vert_bearing_x, -9);
        assert_eq!(actual.vert_bearing_y, 16);
        assert_eq!(actual.vert_advance, 25);
        assert_eq!(actual.hori_bearing_x, 0x1111_1111);
        assert_eq!(actual.hori_bearing_y, 0x2222_2222);
        assert_eq!(actual.hori_advance, 0x3333_3333);
    }

    #[test]
    fn zero_advance_uses_wrapping_twelve_tenths_height() {
        let mut actual = metrics(-11, 20);
        unsafe { ft_synthesize_vertical_metrics(&mut actual, 0) };

        assert_eq!(actual.vert_bearing_x, 5);
        assert_eq!(actual.vert_bearing_y, 2);
        assert_eq!(actual.vert_advance, 24);

        let mut wrapped = metrics(i32::MIN, 0x3000_0000);
        unsafe { ft_synthesize_vertical_metrics(&mut wrapped, 0) };
        assert_eq!(wrapped.vert_bearing_x, 1_073_741_824);
        assert_eq!(wrapped.vert_advance, 107_374_182);
        assert_eq!(wrapped.vert_bearing_y, -348_966_093);
    }

    #[test]
    fn signed_halves_truncate_toward_zero_after_wrapping_subtraction() {
        let mut negative = metrics(-5, 7);
        unsafe { ft_synthesize_vertical_metrics(&mut negative, 2) };
        assert_eq!(negative.vert_bearing_x, 2);
        assert_eq!(negative.vert_bearing_y, -2);

        let mut wrapped = metrics(3, i32::MIN);
        unsafe { ft_synthesize_vertical_metrics(&mut wrapped, i32::MAX) };
        assert_eq!(wrapped.vert_bearing_x, -1);
        assert_eq!(wrapped.vert_bearing_y, 0);
        assert_eq!(wrapped.vert_advance, i32::MAX);
    }
}
