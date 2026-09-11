//! A fixed-width fourteen-byte copy helper.

/// copy_fourteen_bytes — original: `FUN_082231c0` @ **0x082231c0** (**36
/// bytes exactly**, `0x082231c0..0x082231e0`; `0x082231e4` opens the distinct
/// next function).
///
/// Decoding every ARM B/BL immediate in `osos.dec` verifies **nine direct
/// inbound `bl` call sites**, all unconditional; there are no predicated BL
/// forms, direct tail branches, or aligned DATA-word references. The body
/// invokes the IRAM memcpy veneer (`bl 0x08037df8`) for the first 13 bytes,
/// then loads and stores byte 13, and returns the original `dst` in r0. Thus
/// the final byte is read only after the forward grouped copy has completed.
///
/// Deliberate deviations: the port calls
/// [`crate::libc::memcpy::memcpy_forward_words`] directly instead of its ROM
/// veneer; the callee behavior is otherwise identical.
///
/// # Safety
///
/// `src` and `dst` must be four-byte aligned and valid for fourteen byte reads
/// and writes, respectively. The ranges may overlap; their behavior follows
/// the original's forwarded 8-byte, 4-byte, 1-byte, then final-byte sequence.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_fourteen_bytes(dst: *mut u8, src: *const u8) -> *mut u8 {
    crate::libc::memcpy::memcpy_forward_words(dst, src, 13);
    dst.add(13).write(src.add(13).read());
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_fourteen_bytes;

    #[repr(align(4))]
    struct AlignedBytes([u8; 48]);

    /// Independent model of the original's 8-byte, 4-byte, 1-byte, then
    /// trailing-byte transfer sequence. Each word group loads before storing.
    fn reference_copy_fourteen_bytes(bytes: &mut [u8], dst: usize, src: usize) {
        let first_eight = [
            bytes[src], bytes[src + 1], bytes[src + 2], bytes[src + 3],
            bytes[src + 4], bytes[src + 5], bytes[src + 6], bytes[src + 7],
        ];
        bytes[dst..dst + 8].copy_from_slice(&first_eight);

        let next_four = [bytes[src + 8], bytes[src + 9], bytes[src + 10], bytes[src + 11]];
        bytes[dst + 8..dst + 12].copy_from_slice(&next_four);

        bytes[dst + 12] = bytes[src + 12];
        bytes[dst + 13] = bytes[src + 13];
    }

    #[test]
    fn copies_fourteen_bytes_and_returns_destination() {
        let source = AlignedBytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x12, 0x13,
        ]);
        let mut destination = AlignedBytes([0xa5; 48]);

        let returned = unsafe {
            copy_fourteen_bytes(destination.0.as_mut_ptr(), source.0.as_ptr())
        };

        assert_eq!(returned, destination.0.as_mut_ptr());
        assert_eq!(&destination.0[..14], &source.0[..14]);
        assert!(destination.0[14..].iter().all(|&byte| byte == 0xa5));
    }

    #[test]
    fn matches_grouped_forward_copy_for_every_word_aligned_overlap() {
        for dst in (0..=32).step_by(4) {
            let src = 16;
            let initial = AlignedBytes([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            ]);
            let mut expected = AlignedBytes(initial.0);
            let mut actual = AlignedBytes(initial.0);

            reference_copy_fourteen_bytes(&mut expected.0, dst, src);
            let returned = unsafe {
                copy_fourteen_bytes(actual.0.as_mut_ptr().add(dst), actual.0.as_ptr().add(src))
            };

            assert_eq!(returned, unsafe { actual.0.as_mut_ptr().add(dst) }, "dst={dst}");
            assert_eq!(actual.0, expected.0, "dst={dst}");
        }
    }
}
