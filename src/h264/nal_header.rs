//! `h264_nal_header_parse` — original: `FUN_082c5da8` @ 0x082c5da8
//! (36 bytes, 9 instructions, all code; 3 inbound plain `bl` call sites,
//! no predicated calls).
//!
//! Parses the one-byte H.264 NAL-unit header. A set forbidden_zero_bit
//! (bit 7) returns -1 and leaves both outputs untouched. Otherwise it stores
//! nal_ref_idc (bits 6..5) and nal_unit_type (bits 4..0), then returns 0.
//!
//! Deliberate deviations: none. The ARM body accepts r0 as a word, so this
//! signature does too; bits above the low byte are ignored by the original
//! masks.

/// Decodes the H.264 NAL-unit header fields after rejecting its forbidden bit.
///
/// # Safety
/// On success, `nal_ref_idc` and `nal_unit_type` must each designate writable
/// bytes. They are not dereferenced when bit 7 of `nal_header` is set.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn h264_nal_header_parse(
    nal_header: u32,
    nal_ref_idc: *mut u8,
    nal_unit_type: *mut u8,
) -> i32 {
    if nal_header & 0x80 != 0 {
        return -1;
    }

    nal_ref_idc.write(((nal_header & 0x60) >> 5) as u8);
    nal_unit_type.write((nal_header & 0x1f) as u8);
    0
}

#[cfg(test)]
mod tests {
    use super::h264_nal_header_parse;

    #[test]
    fn decodes_each_reference_priority_and_unit_type() {
        for nal_ref_idc in 0..=3u8 {
            for nal_unit_type in [0, 1, 5, 31] {
                let mut actual_ref_idc = 0xff;
                let mut actual_unit_type = 0xff;
                let header = (nal_ref_idc << 5) | nal_unit_type;

                let status = unsafe {
                    h264_nal_header_parse(header as u32, &mut actual_ref_idc, &mut actual_unit_type)
                };

                assert_eq!(status, 0);
                assert_eq!(actual_ref_idc, nal_ref_idc);
                assert_eq!(actual_unit_type, nal_unit_type);
            }
        }
    }

    #[test]
    fn forbidden_bit_rejects_without_writing_outputs() {
        let mut nal_ref_idc = 0x4a;
        let mut nal_unit_type = 0xb5;

        let status = unsafe { h264_nal_header_parse(0xff, &mut nal_ref_idc, &mut nal_unit_type) };

        assert_eq!(status, -1);
        assert_eq!(nal_ref_idc, 0x4a);
        assert_eq!(nal_unit_type, 0xb5);
    }

    #[test]
    fn forbidden_bit_path_does_not_dereference_outputs() {
        assert_eq!(unsafe { h264_nal_header_parse(0x80, core::ptr::null_mut(), core::ptr::null_mut()) }, -1);
    }

    #[test]
    fn ignores_bits_above_the_nal_header_byte() {
        let mut nal_ref_idc = 0;
        let mut nal_unit_type = 0;

        let status = unsafe { h264_nal_header_parse(0xffff_ff65, &mut nal_ref_idc, &mut nal_unit_type) };

        assert_eq!(status, 0);
        assert_eq!(nal_ref_idc, 3);
        assert_eq!(nal_unit_type, 5);
    }
}
