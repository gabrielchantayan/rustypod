//! Texture wrap-mode resolver used by the video-engine property dispatcher.

/// `texture_wrap_mode` — retailOS `FUN_08260448` @ 0x08260448.
///
/// True extent: 32 bytes, ending before the next leaf at 0x08260468.
/// Raw A32 decoding finds two inbound plain BL calls (0x082505e8 and
/// 0x08250600), zero predicated BL calls, and no outbound BL calls.
/// Resolves GL_REPEAT (0x2901) to 1 and GL_CLAMP_TO_EDGE (0x812f) to 0;
/// all other full-width enum values return -1. The dispatcher uses this
/// result for texture-wrap S/T keys 0x2802/0x2803, rejecting -1 rather
/// than storing it into the frame-slot bytes at +0x107/+0x108.
///
/// Deliberate deviations: none in behavior; Rust expresses the original
/// subtract-and-conditional-return comparisons as a match.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn texture_wrap_mode(mode: u32) -> i32 {
    match mode {
        0x2901 => 1,
        0x812f => 0,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::texture_wrap_mode;

    #[test]
    fn resolves_only_the_two_supported_enums_in_the_entire_u16_domain() {
        for mode in 0..=u16::MAX as u32 {
            let expected = if mode == 0x2901 { 1 } else if mode == 0x812f { 0 } else { -1 };
            assert_eq!(texture_wrap_mode(mode), expected, "mode {mode:#x}");
        }
    }

    #[test]
    fn rejects_high_bits_without_truncating_to_a_gl_enum() {
        for high in [0x0001_0000, 0x8000_0000, 0xffff_0000] {
            for low in [0, 0x2901, 0x812f, 0xffff] {
                assert_eq!(texture_wrap_mode(high | low), -1);
            }
        }
    }
}
