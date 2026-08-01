//! cstr_to_counted_u8 — original: `FUN_08045f14` @ 0x08045f14 (64 bytes).
//!
//! Reference: `/home/gabe/Programming/ipod-decomp/decomp/c/002/08045f14_FUN_08045f14.c`.
//! The destination is a byte-counted string object: byte 0 is its length and
//! bytes 1 onward are its payload. The ARM leaf first clears byte 0, then
//! examines each source byte before testing the current byte counter against
//! `limit`. A non-NUL byte is written at the advancing payload cursor; only
//! then are the source pointer and wrapping u8 counter advanced. It copies no
//! NUL terminator, so either a source NUL or an equal counter ends the loop.
//! In particular, a `limit` above 255 is never equal to the zero-extended u8
//! counter, which can wrap while the payload cursor keeps advancing.

/// Copies a NUL-terminated byte string into a byte-counted destination.
///
/// The destination layout is `[length: u8, payload...]`. The stored length
/// wraps modulo 256 exactly as the original's `ldrb`/`add`/`strb` sequence.
/// No NUL byte is stored in the payload.
///
/// # Safety
/// `src` must point to a readable NUL-terminated byte string, and `dst` must
/// have space for its length byte plus every byte copied before the source NUL
/// or counter equality. The ranges must meet the original's raw-pointer
/// requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cstr_to_counted_u8(
    mut src: *const u8,
    dst: *mut u8,
    limit: u32,
) {
    dst.write_volatile(0);
    let mut payload = dst.add(1);

    loop {
        let byte = src.read_volatile();
        if byte == 0 || u32::from(dst.read_volatile()) == limit {
            return;
        }

        payload.write_volatile(byte);
        payload = payload.add(1);
        src = src.add(1);
        dst.write_volatile(dst.read_volatile().wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;


    /// A slice/iterator model of the ARM leaf, deliberately separate from its
    /// raw-pointer loop and instruction ordering.
    fn reference(src: &[u8], dst: &mut [u8], limit: u32) {
        dst[0] = 0;
        let mut payload_index = 1;
        let mut length = 0u8;
        for &byte in src {
            if byte == 0 || u32::from(length) == limit {
                return;
            }
            dst[payload_index] = byte;
            payload_index += 1;
            length = length.wrapping_add(1);
            dst[0] = length;
        }
        panic!("reference source must be NUL terminated");
    }

    fn compare_with_reference(src: &[u8], initial_dst: &[u8], limit: u32) -> Vec<u8> {
        let mut expected = initial_dst.to_vec();
        reference(src, &mut expected, limit);

        let mut actual = initial_dst.to_vec();
        unsafe { cstr_to_counted_u8(src.as_ptr(), actual.as_mut_ptr(), limit) };
        assert_eq!(actual, expected, "limit={limit:#x}, source={src:?}");
        actual
    }

    #[test]
    fn empty_source_exits_before_writing_payload() {
        let initial = [0xa5, 0xcc, 0xcc, 0xcc];
        let actual = compare_with_reference(&[0], &initial, 17);
        assert_eq!(actual, [0, 0xcc, 0xcc, 0xcc]);
    }

    #[test]
    fn counter_equality_exits_at_the_limit_boundary() {
        let initial = [0xa5; 8];
        let actual = compare_with_reference(b"abcd\0", &initial, 3);
        assert_eq!(actual, [3, b'a', b'b', b'c', 0xa5, 0xa5, 0xa5, 0xa5]);

        // Equality is tested before the next byte is stored: a zero limit
        // observes the first non-NUL source byte but leaves no payload.
        let actual = compare_with_reference(b"a\0", &initial, 0);
        assert_eq!(actual, [0, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5]);
    }

    #[test]
    fn counter_wrap_does_not_reuse_the_payload_cursor() {
        let mut src = vec![0x5au8; 257];
        src.push(0);
        let initial = vec![0xa5u8; 260];
        let actual = compare_with_reference(&src, &initial, 0x100);

        assert_eq!(actual[0], 1, "257 copies wrap the stored u8 length");
        assert!(actual[1..258].iter().all(|&byte| byte == 0x5a));
        assert_eq!(&actual[258..], &[0xa5, 0xa5]);
    }

    #[test]
    fn destination_uses_a_length_byte_then_payload_without_a_nul() {
        let mut actual = [0x11u8, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0x22];
        let mut expected = actual;
        reference(b"cat\0", &mut expected[1..6], 9);

        unsafe { cstr_to_counted_u8(b"cat\0".as_ptr(), actual.as_mut_ptr().add(1), 9) };
        assert_eq!(actual, expected);
        assert_eq!(actual, [0x11, 3, b'c', b'a', b't', 0xa5, 0x22]);
    }
}
