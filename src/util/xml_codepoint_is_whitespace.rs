//! `xml_codepoint_is_whitespace` — original: `FUN_0825d2fc` @ `0x0825d2fc`
//! (**28 bytes**, `0x0825d2fc..0x0825d317`; the next real function begins at
//! `0x0825d318` with `push {r4, lr}`).
//!
//! Decoding the function's seven A32 words shows four conditional comparisons
//! of `r1` against XML's ASCII whitespace codepoints, followed by `moveq r0,#1`
//! and `movne r0,#0`. It reads neither `r0` nor `r2`; callers conventionally
//! pass the reader slot in `r0` and duplicate the codepoint in `r2`.
//! Firmware-wide raw-word inspection confirms three plain unconditional `bl`
//! call sites (at `0x0825d330`, `0x0825d36c`, and `0x0825d450`) and no
//! predicated `bl` call sites.
//!
//! ## Deliberate deviations
//!
//! None.

/// Returns whether `codepoint` is one of XML's four ASCII whitespace codepoints.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xml_codepoint_is_whitespace(
    _reader_slot: *mut *mut u8,
    codepoint: u32,
    _duplicate_codepoint: u32,
) -> u32 {
    u32::from(matches!(codepoint, 0x20 | 0x09 | 0x0d | 0x0a))
}

#[cfg(test)]
mod tests {
    use super::xml_codepoint_is_whitespace;
    use core::ptr;

    fn reference_xml_codepoint_is_whitespace(codepoint: u32) -> u32 {
        u32::from(codepoint == 0x20 || codepoint == 0x09 || codepoint == 0x0d || codepoint == 0x0a)
    }

    #[test]
    fn recognizes_exactly_the_four_xml_whitespace_codepoints() {
        for codepoint in 0..=0xff {
            unsafe {
                assert_eq!(xml_codepoint_is_whitespace(ptr::null_mut(), codepoint, !codepoint), reference_xml_codepoint_is_whitespace(codepoint), "codepoint {codepoint:#x}");
            }
        }
    }

    #[test]
    fn ignores_the_reader_slot_and_duplicate_codepoint() {
        let mut reader = ptr::null_mut();
        let reader_slot = ptr::addr_of_mut!(reader);
        for codepoint in [0, 0x0b, 0x0c, 0x21, 0x85, 0xa0, 0x100, 0xffff, u32::MAX] {
            unsafe {
                assert_eq!(xml_codepoint_is_whitespace(reader_slot, codepoint, 0x20), 0, "codepoint {codepoint:#x}");
            }
        }
    }
}
