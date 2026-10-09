//! Fixed SCSI caching mode page for MODE SENSE.
//!
//! Original `FUN_080fa698` @ 0x080fa698, true extent
//! [0x080fa698, 0x080fa704): 108 instruction bytes, no literals; the next
//! function starts with push {r3,r4,r5,r6,r7,r8,r9,lr}. Independent raw A32
//! decoding finds two plain incoming BLs (0x080fb0a8, 0x080fb138), zero
//! predicated incoming BLs, and zero outgoing calls.
//!
//! Caller 0x080faec0 selects caching page 8 or all pages 0x3f. Write
//! 88 12 followed by eighteen zero bytes, ignoring the receiver. Always
//! write all twenty bytes regardless of requested length. Return length
//! + 1 for unsigned lengths <= 20, otherwise 20; length 20 returns 21.
//!
//! Deliberate deviations: none in observable behavior. Volatile byte stores
//! preserve write width/order and prevent libc substitution.

use core::ptr;

/// # Safety
/// `output` must be writable for twenty bytes regardless of `requested_length`.
/// The opaque receiver is ignored and may be NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scsi_caching_page_write(
    _receiver: *const u8,
    output: *mut u8,
    requested_length: u32,
) -> u32 {
    ptr::write_volatile(output, 0x88);
    ptr::write_volatile(output.add(1), 18);
    for offset in 2..20 {
        ptr::write_volatile(output.add(offset), 0);
    }
    if requested_length <= 20 { requested_length + 1 } else { 20 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_page_written_even_for_short_lengths_and_unaligned_outputs() {
        let expected = [0x88, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for alignment in 0..4 {
            for length in 0..=22 {
                let mut storage = [0xa5; 28];
                let start = 4 + alignment;
                let result = unsafe {
                    scsi_caching_page_write(
                        ptr::null(), storage.as_mut_ptr().add(start), length,
                    )
                };
                assert_eq!(&storage[start..start + 20], &expected);
                assert!(storage[..start].iter().all(|&byte| byte == 0xa5));
                assert!(storage[start + 20..].iter().all(|&byte| byte == 0xa5));
                assert_eq!(result, if length < 21 { length + 1 } else { 20 });
            }
        }
    }

    #[test]
    fn unsigned_large_lengths_return_twenty_without_overflow() {
        for length in [0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let mut output = [0xff; 20];
            let result = unsafe {
                scsi_caching_page_write(ptr::null(), output.as_mut_ptr(), length)
            };
            assert_eq!(result, 20);
            assert_eq!(output, [0x88, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        }
    }
}
