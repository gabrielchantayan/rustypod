//! Select a buffer and locate its byte-offset field.
//!
//! Original: `FUN_08213c00` @ 0x08213c00; true extent 60 bytes,
//! ending at the next function's push @ 0x08213c3c. Raw A32 scan:
//! two incoming plain BLs (0x081e18d4, 0x08213c50), zero predicated
//! BLs, and zero outbound calls.
//!
//! When requested, use the first pointer if non-null; otherwise use the
//! second pointer. Return buffer + its first unsigned byte and write the
//! byte there, zero-extended, to the output word. If the selected buffer
//! is null, return null without writing the output. Callers use the pair
//! at object + 0x6c; 0x08213c3c uses the returned byte as another offset.
//! No callee seams or deliberate behavioral deviations. Native pointers
//! in a repr(C) pair preserve target offsets +0/+4 without truncating host
//! pointers. The owning buffer format remains unidentified.

/// Two buffer pointers, at +0 and +4 on the 32-bit firmware target.
#[repr(C)]
pub struct BufferPointerPair {
    pub first: *const u8,
    pub second: *const u8,
}

/// Locate the selected buffer's byte-offset field and read its value.
///
/// # Safety
/// `buffers` must be aligned and readable for the pointer fields accessed.
/// A non-null selected buffer must contain its first byte and the byte at
/// that unsigned offset. On that path, `value` must be aligned and writable
/// for one u32; on the null-buffer path it is not accessed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_buffer_offset_byte(
    buffers: *const BufferPointerPair,
    value: *mut u32,
    prefer_first: u32,
) -> *const u8 {
    let mut buffer = core::ptr::null();
    if prefer_first != 0 {
        buffer = (*buffers).first;
    }
    if buffer.is_null() {
        buffer = (*buffers).second;
    }
    if buffer.is_null() {
        return core::ptr::null();
    }
    let field = buffer.add(*buffer as usize);
    *value = *field as u32;
    field
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_and_all_unsigned_offsets_match_reference() {
        let mut first = [0u8; 256];
        let mut second = [0u8; 256];
        for offset in 0..=255usize {
            first.fill(0xe1);
            second.fill(0xb7);
            first[0] = offset as u8;
            second[0] = offset as u8;
            for prefer_first in [0, 1, 2, u32::MAX] {
                for first_present in [false, true] {
                    for second_present in [false, true] {
                        let pair = BufferPointerPair {
                            first: if first_present { first.as_ptr() } else { core::ptr::null() },
                            second: if second_present { second.as_ptr() } else { core::ptr::null() },
                        };
                        // Reference selection uses fixture state, not the port's pointer branches.
                        let expected = if prefer_first != 0 && first_present {
                            Some(&first)
                        } else if second_present {
                            Some(&second)
                        } else {
                            None
                        };
                        let mut value = 0xfeed_beef;
                        let result = unsafe { selected_buffer_offset_byte(&pair, &mut value, prefer_first) };
                        match expected {
                            Some(bytes) => {
                                assert_eq!(result, unsafe { bytes.as_ptr().add(offset) });
                                assert_eq!(value, bytes[offset] as u32);
                            }
                            None => {
                                assert!(result.is_null());
                                assert_eq!(value, 0xfeed_beef);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn absent_selected_buffer_does_not_access_output() {
        let first = [0u8];
        let pair = BufferPointerPair { first: first.as_ptr(), second: core::ptr::null() };
        assert!(unsafe { selected_buffer_offset_byte(&pair, core::ptr::null_mut(), 0) }.is_null());
    }
}
