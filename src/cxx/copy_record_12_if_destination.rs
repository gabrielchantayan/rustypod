//! copy_record_12_if_destination — original: `FUN_083d7e1c` @ 0x083d7e1c (40 bytes).
//!
//! Raw `osos.dec` words establish the exact ten-instruction extent
//! 0x083d7e1c..0x083d7e43: `movs r0,r1; bxeq lr`, two aligned word loads and
//! stores at +0x00/+0x04, then a byte load/store at +0x08 masked with one.
//! `movs r0,r1` at 0x083d7e44 begins the next independent function. Whole-image
//! A32 decoding finds two inbound plain `bl` sites (0x083e8f40, 0x083e95b0), no
//! inbound predicated `bl` sites, and no outbound calls.
//!
//! Algorithm: return `destination`; when it is non-null, copy the two leading
//! aligned words and canonicalize the low-bit boolean byte at +0x08. The
//! context argument is overwritten before it is read. No deliberate deviations.

/// Copy a 12-byte record when a destination is present.
///
/// # Safety
///
/// When `destination` is non-null, `source` must be readable and `destination`
/// writable for two aligned `u32` words plus one byte at offset eight.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_record_12_if_destination(
    _context: *mut u8,
    destination: *mut u8,
    source: *const u8,
) -> *mut u8 {
    if destination.is_null() {
        return destination;
    }

    (destination as *mut u32).write((source as *const u32).read());
    (destination.add(4) as *mut u32).write((source.add(4) as *const u32).read());
    destination.add(8).write(source.add(8).read() & 1);
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_record_12_if_destination;

    #[test]
    fn null_destination_returns_null_without_reading_source() {
        let returned = unsafe {
            copy_record_12_if_destination(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::dangling(),
            )
        };

        assert!(returned.is_null());
    }

    #[test]
    fn copies_aligned_words_and_canonicalizes_boolean_byte() {
        let source = [0x10u8, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0xfe, 0xa9, 0xba, 0xcb];
        let mut destination = [0xa5u8; 12];

        let returned = unsafe {
            copy_record_12_if_destination(
                core::ptr::null_mut(),
                destination.as_mut_ptr(),
                source.as_ptr(),
            )
        };

        assert_eq!(&destination[..8], &source[..8]);
        assert_eq!(destination[8], 0);
        assert_eq!(&destination[9..], &[0xa5, 0xa5, 0xa5]);
        assert_eq!(returned, destination.as_mut_ptr());
    }

    #[test]
    fn preserves_set_boolean_bit() {
        let source = [0u8, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 0];
        let mut destination = [0u8; 12];

        unsafe {
            copy_record_12_if_destination(
                core::ptr::null_mut(),
                destination.as_mut_ptr(),
                source.as_ptr(),
            );
        }

        assert_eq!(destination[8], 1);
    }
}
