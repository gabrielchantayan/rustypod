//! Input-state status byte — `FUN_081139c8` @ load address 0x081139c8.
//! True extent: 28 bytes, ending at the independent byte-field setter at
//! 0x081139e4. Raw words: e92d4010 e3a04000 eb0224c5 e3500000
//! 15d04073 e1a00004 e8bd8010. Whole-image aligned A32 decoding finds
//! two inbound plain BLs (0x08101504, 0x081018e0), zero predicated BLs,
//! and one outbound plain BL to input_state_buffer_get @ 0x0819ccec.
//!
//! Obtain the input-state buffer, return zero if null, otherwise return its
//! unsigned byte at +0x73 without boolean normalization. Both callers branch
//! on zero/nonzero. The byte's stronger meaning is not established. Reuse the
//! existing fixed-address buffer accessor; no new callee seam. Volatile read
//! preserves the single live-state byte access. Deliberate deviations: none.
//! ARM LLVM propagates the getter's fixed address, removing its BL and the
//! unreachable null arm; generated code loads byte 0x08a779bf directly.

#[inline]
unsafe fn status_byte(buffer: *const u8) -> u8 {
    if buffer.is_null() { 0 } else { buffer.add(0x73).read_volatile() }
}

/// Read the firmware input-state status byte.
///
/// # Safety
/// The firmware buffer returned by `input_state_buffer_get` must be readable
/// at +0x73, with no concurrent conflicting access.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn input_state_status_byte() -> u8 {
    status_byte(super::input_state_buffer_get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_and_all_unsigned_byte_values_match_reference() {
        assert_eq!(unsafe { status_byte(core::ptr::null()) }, 0);
        for shift in 0..4 {
            let mut bytes = [0xa5u8; 0x78];
            for value in 0..=255u8 {
                bytes[shift + 0x73] = value;
                let before = bytes;
                assert_eq!(unsafe { status_byte(bytes.as_ptr().add(shift)) }, value);
                assert_eq!(bytes, before);
            }
        }
    }

    #[test]
    fn exported_accessor_reads_live_fixed_buffer_byte() {
        let Some(page) = crate::testing::try_map_u32_slab(
            crate::testing::hints::INPUT_STATE_STATUS_BYTE, 0x1000,
        ) else {
            crate::testing::note_missing_u32_fixture("input_state_status_byte");
            return;
        };
        assert_eq!(page as usize, crate::testing::hints::INPUT_STATE_STATUS_BYTE);
        unsafe {
            let field = super::super::input_state_buffer_get().add(0x73);
            for value in [0, 1, 0x7f, 0x80, 0xff, 0] {
                field.write_volatile(value);
                assert_eq!(input_state_status_byte(), value);
            }
        }
    }
}
