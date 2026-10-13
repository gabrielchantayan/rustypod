//! Bounded payload copy and versioned record decode.
//!
//! Original: FUN_0802997c @ 0x0802997c, 156 bytes, ending at the next
//! PUSH @ 0x08029a18. Raw A32 decoding verifies two incoming plain BLs
//! (0x08029d20, 0x0802a094), two outgoing plain BLs (0x08029630,
//! 0x0802974c), and zero predicated BLs in either direction.
//!
//! Compare the wrapping consumed+length sum with the signed input limit.
//! On success copy bytes forward, update consumed then cursor, and decode
//! versions 1/2 through the legacy helper or signed versions >=3 through
//! the extended helper. Other versions return 4 AFTER consuming the bytes.
//! An oversized payload returns 4 without mutation. Negative lengths copy
//! nothing but still update both fields using wrapping arithmetic.
//!
//! Deliberate deviations: native pointer cursor on hosts (four bytes on
//! target); volatile byte accesses retain forward overlapping-copy behavior
//! and prevent libc substitution. Unported decoders remain fixed-address
//! firmware calls, with explicit host seams that panic unless installed.

use core::ptr;

type DecodeRecord = unsafe extern "C" fn(i32, i32, u32, *mut u8, *mut u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_decoder(_: i32, _: i32, _: u32, _: *mut u8, _: *mut u32) -> u32 {
    panic!("buffered_record_decode requires a host record decoder")
}

/// Host equivalents of the verified legacy (0x08029630) and extended
/// (0x0802974c) record decoders. Install only with exclusive module access.
#[cfg(not(target_os = "none"))]
pub static mut LEGACY_RECORD_DECODE: DecodeRecord = missing_decoder;
#[cfg(not(target_os = "none"))]
pub static mut EXTENDED_RECORD_DECODE: DecodeRecord = missing_decoder;

/// # Safety
/// Cursor and consumed slots must be valid and aligned. For positive lengths
/// the source and scratch must cover `length` bytes; overlapping bytes are
/// copied forward, not with memmove semantics. The selected retail decoder's
/// input/output layout and size requirements must also hold. Slots may alias
/// payload bytes; accesses preserve the original load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffered_record_decode(
    input_limit: i32, version: i32, length: i32, mode: u32,
    cursor: *mut *const u8, consumed: *mut i32, scratch: *mut u8,
    output: *mut u32,
) -> u32 {
    let used = unsafe { ptr::read_volatile(consumed) };
    let source = unsafe { ptr::read_volatile(cursor) };
    if used.wrapping_add(length) > input_limit { return 4; }
    let mut index = 0i32;
    while index < length {
        unsafe {
            let byte = ptr::read_volatile(source.wrapping_offset(index as isize));
            ptr::write_volatile(scratch.wrapping_offset(index as isize), byte);
        }
        index += 1;
    }
    let next = source.wrapping_offset(length as isize);
    unsafe {
        let used = ptr::read_volatile(consumed);
        ptr::write_volatile(consumed, used.wrapping_add(length));
        ptr::write_volatile(cursor, next);
    }
    let decoder: DecodeRecord;
    if version == 1 || version == 2 {
        #[cfg(target_os = "none")]
        { decoder = unsafe { core::mem::transmute::<usize, DecodeRecord>(0x0802_9630) }; }
        #[cfg(not(target_os = "none"))]
        { decoder = unsafe { ptr::addr_of!(LEGACY_RECORD_DECODE).read() }; }
    } else if version >= 3 {
        #[cfg(target_os = "none")]
        { decoder = unsafe { core::mem::transmute::<usize, DecodeRecord>(0x0802_974c) }; }
        #[cfg(not(target_os = "none"))]
        { decoder = unsafe { ptr::addr_of!(EXTENDED_RECORD_DECODE).read() }; }
    } else { return 4; }
    unsafe { decoder(length, version, mode, scratch, output) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_extent_preserves_all_state_even_for_valid_versions() {
        for version in [1, 2, 3, i32::MAX] {
            let input = [10, 20, 30];
            let mut cursor = input.as_ptr();
            let mut consumed = 7;
            let mut scratch = [0xaa; 5];
            let mut output = [0xdeadbeef; 4];
            assert_eq!(unsafe { buffered_record_decode(9, version, 3, 1,
                &mut cursor, &mut consumed, scratch.as_mut_ptr(), output.as_mut_ptr()) }, 4);
            assert_eq!(cursor, input.as_ptr());
            assert_eq!(consumed, 7);
            assert_eq!(scratch, [0xaa; 5]);
            assert_eq!(output, [0xdeadbeef; 4]);
        }
    }

    #[test]
    fn invalid_versions_consume_exact_boundary_with_unaligned_bytes() {
        for version in [i32::MIN, -1, 0] {
            for length in 0..=16 {
                let input = [0x5a; 18];
                let source = unsafe { input.as_ptr().add(1) };
                let mut cursor = source;
                let mut consumed = 11;
                let mut scratch = [0xaa; 18];
                let mut output = [0xdeadbeef; 4];
                assert_eq!(unsafe { buffered_record_decode(11 + length, version, length, 0,
                    &mut cursor, &mut consumed, scratch.as_mut_ptr().add(1), output.as_mut_ptr()) }, 4);
                assert_eq!(consumed, 11 + length);
                assert_eq!(cursor, source.wrapping_offset(length as isize));
                for (i, byte) in scratch.iter().enumerate() {
                    assert_eq!(*byte, if i >= 1 && i <= length as usize { 0x5a } else { 0xaa });
                }
                assert_eq!(output, [0xdeadbeef; 4]);
            }
        }
    }

    #[test]
    fn forward_overlap_reloads_written_bytes() {
        let mut bytes = [1u8, 2, 3, 4, 5, 6];
        let mut cursor = bytes.as_ptr();
        let mut consumed = 0;
        unsafe { buffered_record_decode(4, 0, 4, 0, &mut cursor,
            &mut consumed, bytes.as_mut_ptr().add(1), ptr::null_mut()) };
        assert_eq!(bytes, [1, 1, 1, 1, 1, 6]);
        assert_eq!(consumed, 4);
        assert_eq!(cursor, bytes.as_ptr().wrapping_add(4));
    }

    #[test]
    fn negative_lengths_and_signed_wrapping_limit_match_arm() {
        for (used, length, limit) in [(7i32, -3i32, 4i32), (i32::MAX, 1, i32::MIN)] {
            let bytes = [9u8; 8];
            let source = bytes.as_ptr().wrapping_add(4);
            let mut cursor = source;
            let mut consumed = used;
            let mut scratch = [0xaa; 4];
            unsafe { buffered_record_decode(limit, 0, length, 0, &mut cursor,
                &mut consumed, scratch.as_mut_ptr(), ptr::null_mut()) };
            assert_eq!(consumed, used.wrapping_add(length));
            assert_eq!(cursor, source.wrapping_offset(length as isize));
            assert_eq!(scratch, if length > 0 { [9, 0xaa, 0xaa, 0xaa] } else { [0xaa; 4] });
        }
    }
}
