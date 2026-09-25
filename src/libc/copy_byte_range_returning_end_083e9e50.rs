//! copy_byte_range_returning_end_083e9e50 — original: `FUN_083e9e50` @ 0x083e9e50 (24 bytes).
//!
//! Raw `osos.dec` words establish the exact six-word ARM body from 0x083e9e50
//! through 0x083e9e64 (`bx lr`); the next real function begins at 0x083e9e68.
//! Full-image A32 decoding finds two inbound direct plain `bl` calls
//! (0x083e6320 and 0x083e6358) and no predicated direct `bl` calls. The body
//! contains no outbound plain or predicated `bl` instructions.
//!
//! It advances `src` from `begin` until it equals `end`, copying each byte in
//! ascending address order to `dst`, then returns the destination end cursor.
//! `begin == end` dereferences neither source nor destination. Overlap has the
//! original forward-propagation behavior.
//!
//! Deliberate deviation: volatile accesses prevent LLVM from replacing this
//! separately linked retail leaf with a memcpy intrinsic; the target-only text
//! section prevents identical-code folding with the adjacent 0x083e9e38 port.

/// Copies `[begin, end)` to `dst` and returns the byte immediately after it.
///
/// # Safety
/// `begin..end` must be a valid contiguous byte range, and `dst` must be valid
/// for the same number of bytes. The ranges may overlap with forward-copy
/// semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_byte_range_returning_end_083e9e50")]
#[inline(never)]
pub unsafe extern "C" fn copy_byte_range_returning_end_083e9e50(
    mut begin: *const u8,
    end: *const u8,
    mut dst: *mut u8,
) -> *mut u8 {
    while begin != end {
        dst.write_volatile(begin.read_volatile());
        begin = begin.add(1);
        dst = dst.add(1);
    }
    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_range_for_alignments_and_returns_end() {
        const LEN: usize = 64;
        let mut source = [0u8; LEN + 8];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }

        for source_offset in 0..4 {
            for destination_offset in 0..4 {
                for len in 0..=LEN {
                    let mut destination = [0xa5u8; LEN + 8];
                    let begin = unsafe { source.as_ptr().add(4 + source_offset) };
                    let end = unsafe { begin.add(len) };
                    let output = unsafe { destination.as_mut_ptr().add(4 + destination_offset) };
                    let returned = unsafe {
                        copy_byte_range_returning_end_083e9e50(begin, end, output)
                    };

                    assert_eq!(returned, unsafe { output.add(len) });
                    assert_eq!(
                        &destination[4 + destination_offset..4 + destination_offset + len],
                        &source[4 + source_offset..4 + source_offset + len],
                    );
                }
            }
        }
    }

    #[test]
    fn overlap_retains_forward_propagation_and_returns_end() {
        let mut bytes = [1u8, 2, 3, 4, 5, 6, 7];
        let begin = bytes.as_ptr();
        let end = unsafe { begin.add(5) };
        let output = unsafe { bytes.as_mut_ptr().add(2) };
        let returned = unsafe { copy_byte_range_returning_end_083e9e50(begin, end, output) };

        assert_eq!(returned, unsafe { output.add(5) });
        assert_eq!(bytes, [1, 2, 1, 2, 1, 2, 1]);
    }

    #[test]
    fn empty_range_returns_destination_without_dereferencing() {
        let returned = unsafe {
            copy_byte_range_returning_end_083e9e50(
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        assert!(returned.is_null());
    }
}
