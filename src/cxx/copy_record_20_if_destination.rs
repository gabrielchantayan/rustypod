//! copy_record_20_if_destination — original: `FUN_083d7cfc` @ 0x083d7cfc (20 bytes).
//!
//! Raw `osos.dec` words establish the exact five-instruction extent
//! 0x083d7cfc..0x083d7d0f: `movs r0,r1`, `mov r1,r2`, `movne r2,#20`, a
//! conditional tail branch to the memcpy veneer at 0x08037df8, and `bx lr`.
//! `movs r0,r1` at 0x083d7d10 begins the next independently linked function.
//! Whole-image ARM branch decoding finds three inbound plain `bl` calls and no
//! inbound predicated `bl` calls; this body contains zero plain and predicated
//! `bl` instructions.
//!
//! Algorithm: if `destination` is non-null, forward-copy one aligned 20-byte
//! record from `source` and return the advanced destination. Otherwise return
//! null without accessing `source`. Deliberate deviation: the stock tail branch
//! enters the IRAM-mirrored memcpy veneer (0x22000188); this port calls the
//! already-ported memcpy body directly, preserving its grouped forward-copy
//! overlap behavior and r0 result.

use crate::libc::memcpy::memcpy_forward_words;

/// Copy a 20-byte record when a destination is present.
///
/// The first ABI argument is retained because stock receives a container
/// context in r0 but overwrites r0 with `destination` before testing it.
///
/// # Safety
///
/// When `destination` is non-null, both ranges must be valid and four-byte
/// aligned for 20 bytes. Overlap has `memcpy_forward_words`' forward grouped
/// load/store behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_record_20_if_destination(
    _context: *mut u8,
    destination: *mut u8,
    source: *const u8,
) -> *mut u8 {
    if destination.is_null() {
        core::ptr::null_mut()
    } else {
        memcpy_forward_words(destination, source, 20)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_record_20_if_destination;

    #[test]
    fn null_destination_returns_null_without_reading_source() {
        let result = unsafe {
            copy_record_20_if_destination(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::dangling(),
            )
        };
        assert!(result.is_null());
    }

    #[test]
    fn copies_one_complete_record_and_returns_its_end() {
        let source = [
            0x10u8, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9,
            0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b,
        ];
        let mut destination = [0u8; 20];

        let result = unsafe {
            copy_record_20_if_destination(
                core::ptr::null_mut(),
                destination.as_mut_ptr(),
                source.as_ptr(),
            )
        };

        assert_eq!(destination, source);
        assert_eq!(result, unsafe { destination.as_mut_ptr().add(20) });
    }

    #[test]
    fn preserves_memcpy_grouped_forward_overlap() {
        let mut bytes: [u32; 8] = [
            0x0302_0100, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c,
            0x1312_1110, 0x1716_1514, 0x1f1e_1d1c, 0x2322_2120,
        ];
        let base = bytes.as_mut_ptr() as *mut u8;

        unsafe {
            copy_record_20_if_destination(core::ptr::null_mut(), base.add(4), base);
        }

        assert_eq!(bytes, [
            0x0302_0100, 0x0302_0100, 0x0706_0504, 0x0b0a_0908,
            0x0f0e_0d0c, 0x0f0e_0d0c, 0x1f1e_1d1c, 0x2322_2120,
        ]);
    }
}
