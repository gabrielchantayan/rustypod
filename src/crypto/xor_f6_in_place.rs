//! In-place XOR-F6 deobfuscation used by the FairPlay/DRM lookup-table setup.
//!
//! `xor_f6_in_place` — original: `FUN_0835206c` @ 0x0835206c (48 bytes;
//! 16 call sites, binary-scanned ARM B/BL words).
//!
//! The exact extent is 0x0835206c..0x0835209c: the next separately entered
//! function starts at 0x0835209c. The retail loop uses a signed byte count:
//! for each index while `index < len`, it loads the byte, XORs it with `0xf6`,
//! and stores it back immediately. Non-positive lengths do not dereference the
//! pointer. There is no NULL guard when `len > 0`.
//!
//! All 16 direct callers are unconditional `bl` instructions in the
//! 0x0804b264..0x0804b31c lookup-table initialization sequence; no predicated
//! `bl` forms or tail branches target this address. That sequence decodes
//! sixteen consecutive 0x100-byte lookup-table pages before using them.
//!
//! Deliberate deviations: none.

/// XORs each of the first `len` bytes at `bytes` with `0xf6` in place.
///
/// # Safety
/// When `len` is positive, `bytes` must be valid for `len` readable and
/// writable bytes. It may be null only when `len <= 0`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.xor_f6_in_place"]
pub unsafe extern "C" fn xor_f6_in_place(bytes: *mut u8, len: i32) {
    let mut index = 0i32;
    while index < len {
        let byte = bytes.add(index as usize);
        byte.write_volatile(byte.read_volatile() ^ 0xf6);
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::xor_f6_in_place;

    #[test]
    fn xors_exact_requested_range_at_every_byte_alignment() {
        for offset in 0..4 {
            for len in 0..=64usize {
                let mut actual = [0xa5u8; 72];
                for (index, byte) in actual.iter_mut().enumerate() {
                    *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
                }
                let mut expected = actual;
                for byte in &mut expected[offset..offset + len] {
                    *byte ^= 0xf6;
                }

                unsafe { xor_f6_in_place(actual[offset..].as_mut_ptr(), len as i32) };

                assert_eq!(actual, expected, "offset={offset}, len={len}");
            }
        }
    }

    #[test]
    fn zero_and_negative_lengths_leave_memory_and_null_untouched() {
        let original = [0x00, 0xf6, 0x5a, 0xff, 0x11, 0x80];
        let mut actual = original;

        unsafe {
            xor_f6_in_place(actual.as_mut_ptr(), 0);
            xor_f6_in_place(actual.as_mut_ptr(), -1);
            xor_f6_in_place(core::ptr::null_mut(), 0);
            xor_f6_in_place(core::ptr::null_mut(), -123);
        }

        assert_eq!(actual, original);
    }
}
