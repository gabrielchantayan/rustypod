//! Source-over compositing for one four-byte RGBA pixel.
//!
//! `rgba_source_over` — original: `FUN_080e779c` @ **0x080e779c** (212 bytes,
//! `0x080e779c..0x080e7870`). Raw `osos.dec` decoding ends at the `pop` at
//! `0x080e786c`; the next independent function begins with `push` at
//! `0x080e7870`. The function has one plain direct `bl` to `__rt_sdiv`
//! (`0x08031568`) and no predicated `bl` instructions; its four inbound call
//! sites are plain `bl` forms.
//!
//! For a zero source alpha, copies all four destination bytes. Otherwise,
//! combines each RGB channel using the source alpha and destination alpha plus
//! one, computes the resulting alpha, then divides 1024 by it before the final
//! Q10 scale. ARM `mul`/`mla` arithmetic is retained at 32-bit width and each
//! result is stored as its low byte.
//!
//! Deliberate deviations: the Rust loop replaces the ARM's hand-unrolled RGB
//! sequence; its explicit call to the ported `__rt_sdiv` preserves the
//! retailOS signed-division seam.

use crate::runtime::rt_div::__rt_sdiv;

/// Composites `source` over `destination`, writing a four-byte RGBA pixel to
/// `output`. All pointers must be valid for four byte accesses.
#[cfg_attr(target_os = "none", link_section = ".text.rgba_source_over")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rgba_source_over(
    output: *mut u8,
    source: *const u8,
    destination: *const u8,
) {
    unsafe {
        let source_alpha = core::ptr::read(source.add(3));
        if source_alpha == 0 {
            for channel in 0..4 {
                core::ptr::write(output.add(channel), core::ptr::read(destination.add(channel)));
            }
            return;
        }

        let destination_alpha_plus_one = core::ptr::read(destination.add(3)) as i32 + 1;
        let output_alpha = destination_alpha_plus_one
            + ((source_alpha as i32 + 1) * (255 - destination_alpha_plus_one) >> 8);
        let scale = __rt_sdiv(1024, output_alpha);

        for channel in 0..3 {
            let source_term = (source_alpha as i32)
                .wrapping_mul(core::ptr::read(source.add(channel)) as i32)
                .wrapping_add(1);
            let blended = ((core::ptr::read(destination.add(channel)) as i32)
                .wrapping_sub(source_term >> 8))
            .wrapping_mul(destination_alpha_plus_one)
            .wrapping_add(source_term)
            .wrapping_mul(scale)
                >> 10;
            core::ptr::write(output.add(channel), blended as u8);
        }
        core::ptr::write(output.add(3), output_alpha as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::rgba_source_over;

    fn reference(source: [u8; 4], destination: [u8; 4]) -> [u8; 4] {
        if source[3] == 0 {
            return destination;
        }

        let destination_alpha_plus_one = destination[3] as i32 + 1;
        let output_alpha = destination_alpha_plus_one
            + ((source[3] as i32 + 1) * (255 - destination_alpha_plus_one) >> 8);
        let scale = 1024 / output_alpha;
        let mut output = [0; 4];
        for channel in 0..3 {
            let source_term = source[3] as i32 * source[channel] as i32 + 1;
            output[channel] = (((destination[channel] as i32 - (source_term >> 8))
                * destination_alpha_plus_one
                + source_term)
                * scale
                >> 10) as u8;
        }
        output[3] = output_alpha as u8;
        output
    }

    #[test]
    fn transparent_source_copies_destination_including_alpha() {
        let source = [0xde, 0xad, 0xbe, 0];
        let destination = [0x12, 0x34, 0x56, 0x78];
        let mut output = [0xa5; 4];

        unsafe { rgba_source_over(output.as_mut_ptr(), source.as_ptr(), destination.as_ptr()) };

        assert_eq!(output, destination);
    }

    #[test]
    fn composites_extreme_and_partial_alpha_pixels() {
        for (source, destination) in [
            ([0, 0, 0, 1], [255, 128, 1, 0]),
            ([255, 0, 127, 127], [0, 255, 64, 128]),
            ([10, 20, 30, 255], [200, 150, 100, 255]),
        ] {
            let mut output = [0; 4];
            unsafe { rgba_source_over(output.as_mut_ptr(), source.as_ptr(), destination.as_ptr()) };
            assert_eq!(output, reference(source, destination));
        }
    }

    #[test]
    fn permits_output_to_alias_destination() {
        let source = [220, 40, 80, 160];
        let mut destination = [30, 170, 250, 90];
        let expected = reference(source, destination);

        unsafe {
            rgba_source_over(
                destination.as_mut_ptr(),
                source.as_ptr(),
                destination.as_ptr(),
            )
        };

        assert_eq!(destination, expected);
    }
}
