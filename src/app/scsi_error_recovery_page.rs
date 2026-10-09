//! Fixed SCSI read/write error-recovery mode page for MODE SENSE.
//!
//! Original `FUN_080fdaf8` @ 0x080fdaf8, true extent
//! [0x080fdaf8, 0x080fdb48): 80 instruction bytes, no literals; the next
//! function begins with push {r3,r4,r5,r6,r7,r8,r9,lr}. Independent raw A32
//! decoding finds two plain incoming BLs (0x080fb0e4, 0x080fb190), zero
//! predicated incoming BLs, and zero outgoing calls.
//!
//! Caller 0x080faec0 selects page 1 or includes it for all-pages selector
//! 0x3f. Write 81 0a e0 followed by nine zero bytes, ignoring the receiver.
//! Always write all twelve bytes regardless of requested length. Return
//! requested_length + 1 for unsigned lengths <= 12, otherwise 12; length
//! 12 therefore returns 13 rather than a conventional clipped length.
//!
//! Deliberate deviations: none in observable behavior. Volatile byte stores
//! preserve write width/order and prevent libc substitution.

use core::ptr;

/// # Safety
/// `output` must be writable for twelve bytes regardless of `requested_length`.
/// The opaque receiver is ignored and may be NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scsi_error_recovery_page_write(
    _receiver: *const u8,
    output: *mut u8,
    requested_length: u32,
) -> u32 {
    ptr::write_volatile(output, 0x81);
    ptr::write_volatile(output.add(1), 10);
    ptr::write_volatile(output.add(2), 0xe0);
    for offset in 3..12 {
        ptr::write_volatile(output.add(offset), 0);
    }
    if requested_length <= 12 { requested_length + 1 } else { 12 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_page_written_even_for_short_lengths_and_unaligned_outputs() {
        let expected = [0x81, 10, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for alignment in 0..4 {
            for length in 0..=14 {
                let mut storage = [0xa5; 20];
                let start = 4 + alignment;
                let result = unsafe {
                    scsi_error_recovery_page_write(
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
    fn unsigned_large_lengths_return_twelve_without_overflow() {
        for length in [0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let mut output = [0xff; 12];
            let result = unsafe {
                scsi_error_recovery_page_write(ptr::null(), output.as_mut_ptr(), length)
            };
            assert_eq!(result, 12);
            assert_eq!(output, [0x81, 10, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
    }
}
