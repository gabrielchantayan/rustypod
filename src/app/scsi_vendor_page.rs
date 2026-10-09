//! Vendor SCSI MODE SENSE page 0x20, original `FUN_080fd678` @ 0x080fd678.
//! True extent [0x080fd678, 0x080fd6d8): 96 bytes (84 instructions + 12
//! literals), before the next function's push. Raw A32 decoding verifies
//! two plain incoming BLs (0x080fb170, 0x080fb228), no predicated incoming
//! BLs, and one plain outgoing BL to __f2u @ 0x083ec90c.
//!
//! Ignore receiver; write 20 02, set byte 0x089cb1fa to 1, copy byte
//! 0x089cb1f9, then convert the float bits at 0x089cb200 with ADS __f2u
//! and store its low byte. All four bytes are written even for length zero.
//! Return length + 1 for unsigned length <= 4, otherwise 4. The caller
//! 0x080faec0 selects this page for 0x20 and all-pages selector 0x3f.
//! Deliberate deviations: none; local-state helper permits isolated host
//! tests. Volatile accesses preserve firmware access widths and ordering.

//! ARM match review: LLVM inlines the existing __f2u body (37 reported
//! lines versus 21 stock instructions), retaining its saturation/truncation,
//! ordered accesses and unsigned length selection; no new callee seam.
use core::ptr;
use crate::fp::fp_fconv::__f2u;

#[inline(always)]
unsafe fn write_page(output: *mut u8, length: u32, flag: *mut u8,
    value: *const u8, float_bits: *const u32) -> u32 {
    ptr::write_volatile(output, 0x20);
    ptr::write_volatile(output.add(1), 2);
    ptr::write_volatile(flag, 1);
    ptr::write_volatile(output.add(2), ptr::read_volatile(value));
    let converted = __f2u(ptr::read_volatile(float_bits));
    ptr::write_volatile(output.add(3), converted as u8);
    if length <= 4 { length + 1 } else { 4 }
}

/// # Safety
/// `output` must permit four byte writes regardless of requested length.
/// Firmware globals 0x089cb1f9/1fa and aligned word 0x089cb200 must be mapped.
/// The receiver is ignored and may be NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scsi_vendor_page_write(
    _receiver: *const u8, output: *mut u8, requested_length: u32,
) -> u32 {
    write_page(output, requested_length, 0x089c_b1fa as *mut u8,
        0x089c_b1f9 as *const u8, 0x089c_b200 as *const u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_alignment_and_float_conversion() {
        let cases = [(0.0f32.to_bits(), 0), (255.75f32.to_bits(), 255),
            (256.5f32.to_bits(), 0), (511.9f32.to_bits(), 255),
            ((-1.0f32).to_bits(), 0), (f32::INFINITY.to_bits(), 255),
            (f32::NEG_INFINITY.to_bits(), 0), (0x7fc0_1234, 0),
            (1, 0), (4294967296.0f32.to_bits(), 255)];
        for (bits, expected) in cases {
            for start in 0..4 {
                for length in [0, 1, 2, 3, 4, 5, 0x8000_0000, u32::MAX] {
                    let mut buffer = [0xa5; 12];
                    let mut flag = 0x80;
                    let value = 0xe7;
                    let result = unsafe { write_page(buffer.as_mut_ptr().add(start),
                        length, &mut flag, &value, &bits) };
                    assert_eq!(&buffer[start..start + 4], &[0x20, 2, value, expected]);
                    assert!(buffer[..start].iter().all(|&b| b == 0xa5));
                    assert!(buffer[start + 4..].iter().all(|&b| b == 0xa5));
                    assert_eq!(flag, 1);
                    assert_eq!(result, if length <= 4 { length + 1 } else { 4 });
                }
            }
        }
    }

    #[test]
    fn flag_write_precedes_value_read_when_aliased() {
        let mut flag = 0xfeu8;
        let flag_ptr = &mut flag as *mut u8;
        let mut output = [0; 4];
        let bits = 12.9f32.to_bits();
        let result = unsafe { write_page(output.as_mut_ptr(), 4, flag_ptr, flag_ptr, &bits) };
        assert_eq!(output, [0x20, 2, 1, 12]);
        assert_eq!(result, 5);
    }
}
