//! `pixel_format_source_tag_supported` — original: `FUN_0825ecf0` @ 0x0825ecf0
//! (140 bytes; **4 unconditional `bl` call sites**, no predicated `bl` call
//! sites, binary-scanned from `osos.dec`).
//!
//! The complete 35-word leaf begins at `cmn r0,#1`, immediately after the
//! RGB555A1 cursor reader's tail branch at 0x0825ecec, and ends at `bx lr` at
//! 0x0825ed78. The following word is the literal `0x00001401`; 0x0825ed80
//! starts a distinct non-leaf function. The routine rejects unequal or `-1`
//! pixel formats. For equal formats 0..7, it accepts source tags according to
//! the raw jump table: 0..2 require `0x1401`; 3 and 5 additionally allow
//! `0x8363`; 4, 6, and 7 additionally allow `0x8033` or `0x8034`. Equal
//! formats outside that range accept every source tag.
//!
//! # Deliberate deviations
//!
//! The firmware has no symbolic identity for these source-tag values. The port
//! retains their verified numeric values rather than inventing protocol names.

/// Reports whether `source_tag` is supported for a matching pixel format.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn pixel_format_source_tag_supported(
    pixel_format: i32,
    expected_pixel_format: i32,
    source_tag: u32,
) -> bool {
    if pixel_format == -1 || expected_pixel_format == -1 || pixel_format != expected_pixel_format {
        return false;
    }

    match pixel_format {
        0..=2 => source_tag == 0x1401,
        3 | 5 => source_tag == 0x1401 || source_tag == 0x8363,
        4 | 6 | 7 => source_tag == 0x1401 || source_tag == 0x8033 || source_tag == 0x8034,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::pixel_format_source_tag_supported;

    #[test]
    fn rejects_missing_or_different_pixel_formats() {
        for (pixel_format, expected_pixel_format) in [(-1, -1), (-1, 0), (0, -1), (0, 1), (7, 6)] {
            assert!(!pixel_format_source_tag_supported(pixel_format, expected_pixel_format, 0x1401));
        }
    }

    #[test]
    fn accepts_tags_from_each_verified_jump_table_group() {
        for pixel_format in 0..=2 {
            assert!(pixel_format_source_tag_supported(pixel_format, pixel_format, 0x1401));
            assert!(!pixel_format_source_tag_supported(pixel_format, pixel_format, 0x8363));
        }

        for pixel_format in [3, 5] {
            for source_tag in [0x1401, 0x8363] {
                assert!(pixel_format_source_tag_supported(pixel_format, pixel_format, source_tag));
            }
            assert!(!pixel_format_source_tag_supported(pixel_format, pixel_format, 0x8033));
        }

        for pixel_format in [4, 6, 7] {
            for source_tag in [0x1401, 0x8033, 0x8034] {
                assert!(pixel_format_source_tag_supported(pixel_format, pixel_format, source_tag));
            }
            assert!(!pixel_format_source_tag_supported(pixel_format, pixel_format, 0x8363));
        }
    }

    #[test]
    fn accepts_any_source_tag_for_equal_out_of_table_formats() {
        for pixel_format in [-2, 8, i32::MAX] {
            for source_tag in [0, 0x1401, 0x8363, 0xffff_ffff] {
                assert!(pixel_format_source_tag_supported(pixel_format, pixel_format, source_tag));
            }
        }
    }
}
