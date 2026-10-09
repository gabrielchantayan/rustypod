//! Fixed informational-exceptions mode page for the storage response builder.
//!
//! Original `FUN_080fdde4` @ 0x080fdde4, true extent
//! [0x080fdde4, 0x080fde38): 84 instruction bytes, no literals. The next
//! function begins with push {r4,r5,r6,r7,lr}. Independent raw A32 decoding
//! finds two plain incoming BLs (0x080fb154, 0x080fb20c), zero predicated
//! incoming BLs, and zero outgoing calls.
//!
//! Caller 0x080faec0 selects this page for selector 0x1c and includes it for
//! selector 0x3f; its command-byte 0x1a path has the MODE SENSE(6) header.
//! Write 9c 0a 81 02 followed by eight zero bytes, ignoring the receiver.
//! Always write all twelve bytes, even for a zero requested length. Return
//! requested_length + 1 for unsigned lengths <= 12, otherwise 12 (not a
//! conventional min(length, 12): length 12 returns 13).
//!
//! Deliberate deviations: none in observable behavior. Volatile byte stores
//! retain the original write width/order and prevent libc substitution.

use core::ptr;

/// # Safety
/// `output` must be writable for twelve bytes regardless of `requested_length`.
/// The opaque receiver is ignored and may be NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scsi_informational_exceptions_page_write(
    _receiver: *const u8,
    output: *mut u8,
    requested_length: u32,
) -> u32 {
    ptr::write_volatile(output, 0x9c);
    ptr::write_volatile(output.add(1), 10);
    ptr::write_volatile(output.add(2), 0x81);
    ptr::write_volatile(output.add(3), 2);
    for offset in 4..12 {
        ptr::write_volatile(output.add(offset), 0);
    }
    if requested_length <= 12 { requested_length + 1 } else { 12 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_page_written_for_short_lengths_and_unaligned_outputs() {
        let expected = [0x9c, 10, 0x81, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        for alignment in 0..4 {
            for length in 0..=14 {
                let mut storage = [0xa5; 20];
                let start = 4 + alignment;
                let result = unsafe {
                    scsi_informational_exceptions_page_write(
                        ptr::null(), storage.as_mut_ptr().add(start), length,
                    )
                };
                assert_eq!(&storage[start..start + 12], &expected);
                assert!(storage[..start].iter().all(|&byte| byte == 0xa5));
                assert!(storage[start + 12..].iter().all(|&byte| byte == 0xa5));
                assert_eq!(result, if length < 13 { length + 1 } else { 12 });
            }
        }
    }

    #[test]
    fn high_unsigned_lengths_do_not_take_the_short_length_path() {
        for length in [0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let mut output = [0xff; 12];
            let result = unsafe {
                scsi_informational_exceptions_page_write(ptr::null(), output.as_mut_ptr(), length)
            };
            assert_eq!(result, 12);
            assert_eq!(output, [0x9c, 10, 0x81, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
    }
}
