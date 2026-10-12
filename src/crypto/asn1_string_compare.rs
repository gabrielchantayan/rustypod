//! ASN1_STRING_cmp — original: `FUN_0803a25c` @ 0x0803a25c.
//!
//! True extent: 60 bytes, ending at 0x0803a298's next function prologue.
//! Raw-word scan: two plain inbound BLs, zero predicated inbound BLs;
//! body has one plain BL to memcmp @ 0x08030f64, zero predicated BLs.
//! Compare wrapping 32-bit lengths first; if equal, compare exactly that
//! many bytes, then compare wrapping 32-bit ASN.1 types only if bytes match.
//! Ghidra omits memcmp's third argument: r2 retains the left length.
//!
//! Deliberate deviations: none in behavior. Reuse OwnedBuffer's verified
//! ASN1_STRING prefix; its `source` word is the ASN.1 type in this context.
//! Native pointers keep host fixtures valid while preserving target offsets.

use crate::heap::owned_buffer::OwnedBuffer;
use crate::libc::memcmp::memcmp;

/// # Safety
/// Both strings must be non-NULL aligned readable records. When lengths
/// match and are nonzero, both data ranges must be readable for that u32
/// length. Unequal lengths do not access data; zero length permits NULL data.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn asn1_string_compare(left: *const OwnedBuffer, right: *const OwnedBuffer) -> i32 {
    let length = (*left).length;
    let difference = length.wrapping_sub((*right).length) as i32;
    if difference != 0 {
        return difference;
    }
    let difference = memcmp((*left).data, (*right).data, length as usize);
    if difference != 0 {
        return difference;
    }
    (*left).source.wrapping_sub((*right).source) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(length: u32, kind: u32, data: *const u8) -> OwnedBuffer {
        OwnedBuffer { length, source: kind, data: data as *mut u8, context: 0 }
    }

    #[test]
    fn unequal_lengths_return_exact_wrapping_difference_without_reading_data() {
        for (left, right) in [(0, 1), (17, 2), (u32::MAX, 0), (0, u32::MAX), (0x8000_0000, 1)] {
            let a = string(left, 0, core::ptr::null());
            let b = string(right, u32::MAX, core::ptr::null());
            assert_eq!(unsafe { asn1_string_compare(&a, &b) }, left.wrapping_sub(right) as i32);
        }
    }

    #[test]
    fn empty_and_equal_bytes_use_wrapping_type_difference() {
        for bytes in [&b""[..], &b"a\0b\xff"[..]] {
            for (left, right) in [(0, 0), (3, 7), (9, 2), (u32::MAX, 0), (0, u32::MAX), (0x8000_0000, 1)] {
                let data = if bytes.is_empty() { core::ptr::null() } else { bytes.as_ptr() };
                let a = string(bytes.len() as u32, left, data);
                let b = string(bytes.len() as u32, right, data);
                assert_eq!(unsafe { asn1_string_compare(&a, &b) }, left.wrapping_sub(right) as i32);
            }
        }
    }

    #[test]
    fn byte_difference_precedes_type_and_includes_nuls_but_not_trailing_bytes() {
        for length in 1..=16 {
            for mismatch in 0..length {
                let mut a_bytes = [0u8; 20];
                let mut b_bytes = [0u8; 20];
                a_bytes[mismatch] = 0xff;
                b_bytes[mismatch] = 1;
                let a = string(length as u32, 1, a_bytes.as_ptr());
                let b = string(length as u32, 9, b_bytes.as_ptr());
                assert_eq!(unsafe { asn1_string_compare(&a, &b) }, 254);
                assert_eq!(unsafe { asn1_string_compare(&b, &a) }, -254);
            }
        }
        let a = string(3, 7, b"x\0yA".as_ptr());
        let b = string(3, 7, b"x\0yB".as_ptr());
        assert_eq!(unsafe { asn1_string_compare(&a, &b) }, 0);
    }
}
