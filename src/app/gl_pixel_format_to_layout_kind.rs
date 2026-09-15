//! Maps OpenGL ES pixel-format constants to retailOS layout kinds.
//!
//! `gl_pixel_format_to_layout_kind` — original `FUN_08260468` @
//! **0x08260468** (144 bytes, `0x08260468..0x082604f4`; the literal
//! `0x00001906` at `0x082604f8` starts after the body and the distinct next
//! function starts at `0x082604fc`). Decoding every aligned ARM B/BL-immediate
//! word in `osos.dec` finds five direct inbound plain `bl` calls at
//! `0x0824d660`, `0x0824de88`, `0x0824de94`, `0x0825066c`, and `0x08251680`;
//! there are no predicated `bl` calls.
//!
//! The ARM comparison tree recognizes the five OpenGL ES 1.x pixel formats
//! `GL_ALPHA` through `GL_LUMINANCE_ALPHA`, plus their retailOS layout-kind
//! equivalents 1 through 4, and converts each to its layout kind. All other
//! bit patterns return `-1`. Deliberate deviations: the equivalent Rust match
//! replaces the ARM signed comparison tree; it preserves every exact input
//! value and result without dereferencing memory or calling another function.

/// `GL_ALPHA` (0x1906), which maps to layout kind zero.
const GL_ALPHA: u32 = 0x1906;
/// `GL_RGB` (0x1907).
const GL_RGB: u32 = 0x1907;
/// `GL_RGBA` (0x1908).
const GL_RGBA: u32 = 0x1908;
/// `GL_LUMINANCE` (0x1909).
const GL_LUMINANCE: u32 = 0x1909;
/// `GL_LUMINANCE_ALPHA` (0x190a).
const GL_LUMINANCE_ALPHA: u32 = 0x190a;

/// Converts a GL pixel format or an existing retailOS layout kind to a layout kind.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn gl_pixel_format_to_layout_kind(pixel_format: u32) -> i32 {
    match pixel_format {
        GL_ALPHA => 0,
        1 | GL_LUMINANCE => 1,
        2 | GL_LUMINANCE_ALPHA => 2,
        3 | GL_RGB => 5,
        4 | GL_RGBA => 4,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_recognized_gl_formats() {
        assert_eq!(gl_pixel_format_to_layout_kind(GL_ALPHA), 0);
        assert_eq!(gl_pixel_format_to_layout_kind(GL_RGB), 5);
        assert_eq!(gl_pixel_format_to_layout_kind(GL_RGBA), 4);
        assert_eq!(gl_pixel_format_to_layout_kind(GL_LUMINANCE), 1);
        assert_eq!(gl_pixel_format_to_layout_kind(GL_LUMINANCE_ALPHA), 2);
    }

    #[test]
    fn preserves_existing_layout_kinds_and_rejects_other_values() {
        assert_eq!(gl_pixel_format_to_layout_kind(1), 1);
        assert_eq!(gl_pixel_format_to_layout_kind(2), 2);
        assert_eq!(gl_pixel_format_to_layout_kind(3), 5);
        assert_eq!(gl_pixel_format_to_layout_kind(4), 4);
        assert_eq!(gl_pixel_format_to_layout_kind(0), -1);
        assert_eq!(gl_pixel_format_to_layout_kind(5), -1);
        assert_eq!(gl_pixel_format_to_layout_kind(u32::MAX), -1);
    }
}
