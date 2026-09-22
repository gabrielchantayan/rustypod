//! `rgb565_weighted_blend` — original: `FUN_08273fb0` @ `0x08273fb0`
//! (76 executable bytes, `0x08273fb0..0x08273ffc`; two literal words follow,
//! and the next function begins at `0x08274004`). Raw ARM decoding finds no
//! outbound call instructions. Three inbound call sites are plain,
//! unconditional `bl` instructions; none is predicated.
//!
//! Expands RGB565's green field into a separate 32-bit lane, then combines
//! the first colour with weight `phase >> 11` and the second with complementary
//! weight `32 - (phase >> 11)`. It applies the retailOS literal lane biases to
//! each product, shifts each product by five, masks the packed lanes, and
//! collapses the expanded green field back into RGB565.
//!
//! # Deliberate deviations
//!
//! None.

const RGB565_GREEN: u32 = 0x07e0;
const EXPANDED_RGB565_MASK: u32 = 0x07e0_f81f;
const ROUND_BIAS: u32 = 0x01e0_7e0f;

#[inline]
fn expand_rgb565(color: u16) -> u32 {
    let color = u32::from(color);
    (color & !RGB565_GREEN) | ((color & RGB565_GREEN) << 16)
}

/// Blends two RGB565 colours with a Q5 phase value.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn rgb565_weighted_blend(first: u16, second: u16, phase: i32) -> u16 {
    let first = expand_rgb565(first);
    let second = expand_rgb565(second);
    let first_weight = (phase >> 11) as u32;
    let second_weight = 32u32.wrapping_sub(first_weight);
    let blended = first_weight
        .wrapping_mul(first)
        .wrapping_add(ROUND_BIAS)
        .wrapping_shr(5)
        .wrapping_add(
            second_weight
                .wrapping_mul(second)
                .wrapping_add(ROUND_BIAS)
                .wrapping_shr(5),
        )
        & EXPANDED_RGB565_MASK;

    ((blended >> 16) | blended) as u16
}

#[cfg(test)]
mod tests {
    use super::rgb565_weighted_blend;

    fn reference_blend(first: u16, second: u16, phase: i32) -> u16 {
        let first = u32::from(first);
        let first = (first & !0x07e0) | ((first & 0x07e0) << 16);
        let second = u32::from(second);
        let second = (second & !0x07e0) | ((second & 0x07e0) << 16);
        let first_weight = (phase >> 11) as u32;
        let second_weight = 32u32.wrapping_sub(first_weight);
        let packed = first_weight
            .wrapping_mul(first)
            .wrapping_add(0x01e0_7e0f)
            .wrapping_shr(5)
            .wrapping_add(
                second_weight
                    .wrapping_mul(second)
                    .wrapping_add(0x01e0_7e0f)
                    .wrapping_shr(5),
            )
            & 0x07e0_f81f;

        ((packed >> 16) | packed) as u16
    }

    #[test]
    fn phase_endpoints_select_the_opposite_inputs() {
        assert_eq!(rgb565_weighted_blend(0xf81f, 0x07e0, 0), 0x07e0);
        assert_eq!(rgb565_weighted_blend(0xf81f, 0x07e0, 0x10000), 0xf81f);
    }

    #[test]
    fn phases_cover_channel_rounding_boundaries() {
        for phase in [0, 0x07ff, 0x0800, 0x8000, 0xf800, 0xffff, 0x10000] {
            assert_eq!(
                rgb565_weighted_blend(0xf81f, 0x07e0, phase),
                reference_blend(0xf81f, 0x07e0, phase),
                "phase {phase:#x}",
            );
        }
    }

    #[test]
    fn packed_lane_biases_cover_all_rgb565_fields() {
        let first = 0x18c7;
        let second = 0xc735;
        let phase = 0x5800;

        assert_eq!(
            rgb565_weighted_blend(first, second, phase),
            reference_blend(first, second, phase),
        );
    }
}
