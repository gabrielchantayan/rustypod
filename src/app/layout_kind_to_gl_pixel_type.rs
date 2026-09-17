//! Maps retailOS layout kinds to OpenGL ES pixel data types.
//!
//! `layout_kind_to_gl_pixel_type` — original `FUN_082604fc` @
//! **0x082604fc** (40 bytes, `0x082604fc..0x08260524`). The next independently
//! linked leaf starts at `0x08260534`, after the four-word literal pool. A
//! whole-image A32 branch-immediate decode finds four inbound plain `bl` calls
//! at `0x0824df7c`, `0x08250728`, `0x08251704`, and `0x08252a30`; there are no
//! predicated `bl` calls.
//!
//! The ARM comparison chain maps layout kinds 5, 6, and 7 to their packed
//! OpenGL ES pixel types; every other value selects `GL_UNSIGNED_BYTE`.
//! Deliberate deviation: the Rust match replaces conditional literal loads;
//! it preserves all 32-bit inputs and returns without dereferencing memory or
//! calling another function.

/// `GL_UNSIGNED_BYTE`.
const GL_UNSIGNED_BYTE: u32 = 0x1401;
/// `GL_UNSIGNED_SHORT_5_6_5_REV`.
const GL_UNSIGNED_SHORT_5_6_5_REV: u32 = 0x8363;
/// `GL_UNSIGNED_SHORT_4_4_4_4_REV`.
const GL_UNSIGNED_SHORT_4_4_4_4_REV: u32 = 0x8033;
/// `GL_UNSIGNED_SHORT_5_5_5_1_REV`.
const GL_UNSIGNED_SHORT_5_5_5_1_REV: u32 = 0x8034;

/// Selects the OpenGL ES pixel type for a retailOS layout kind.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn layout_kind_to_gl_pixel_type(layout_kind: u32) -> u32 {
    match layout_kind {
        5 => GL_UNSIGNED_SHORT_5_6_5_REV,
        6 => GL_UNSIGNED_SHORT_4_4_4_4_REV,
        7 => GL_UNSIGNED_SHORT_5_5_5_1_REV,
        _ => GL_UNSIGNED_BYTE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_packed_layout_kind() {
        assert_eq!(layout_kind_to_gl_pixel_type(5), GL_UNSIGNED_SHORT_5_6_5_REV);
        assert_eq!(layout_kind_to_gl_pixel_type(6), GL_UNSIGNED_SHORT_4_4_4_4_REV);
        assert_eq!(layout_kind_to_gl_pixel_type(7), GL_UNSIGNED_SHORT_5_5_5_1_REV);
    }

    #[test]
    fn defaults_for_adjacent_and_extreme_layout_kinds() {
        for layout_kind in [0, 1, 4, 8, u32::MAX] {
            assert_eq!(layout_kind_to_gl_pixel_type(layout_kind), GL_UNSIGNED_BYTE);
        }
    }
}
