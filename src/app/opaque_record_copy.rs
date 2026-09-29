//! Opaque 32-byte record copy — original: `FUN_082e066c` @ `0x082e066c`.
//!
//! Raw `osos.dec` establishes the 136-byte extent `0x082e066c..0x082e06f4`:
//! the next `push {r4,r5,r6,lr}` at `0x082e06f4` starts another function.
//! The body has two verified outbound plain unconditional `bl` calls, both to
//! [`forward_byte_copy`]; decoding the complete function finds no predicated
//! `bl` forms. There are two inbound plain unconditional `bl` call sites and
//! no predicated forms.
//!
//! # Algorithm
//!
//! Copy the record's first eight bytes, then bytes `+0x08..+0x0a`, through
//! `forward_byte_copy`. Copy bytes `+0x0b..+0x0d`, halfwords `+0x0e..+0x1a`,
//! and the word at `+0x1c` in the exact load/store order of the retail body.
//!
//! # Deliberate deviations
//!
//! The record remains opaque because callers do not establish field meanings.
//! Volatile scalar accesses preserve the retail load/store ordering, including
//! its repeated copy of halfword `+0x14`, rather than letting LLVM coalesce it.

use core::ptr;

use crate::libc::forward_byte_copy::forward_byte_copy;

/// Copies one opaque 32-byte retailOS record.
///
/// # Safety
/// `dst` and `src` must each be valid for 32 bytes. They must be naturally
/// aligned for the halfword and word fields; overlap retains the original
/// ordered forward-copy behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_record_copy_082e066c")]
#[inline(never)]
pub unsafe extern "C" fn opaque_record_copy(dst: *mut u8, src: *const u8) {
    forward_byte_copy(dst, src, 8);
    forward_byte_copy(dst.add(8), src.add(8), 3);

    copy_byte(dst, src, 0x0b);
    copy_byte(dst, src, 0x0c);
    copy_byte(dst, src, 0x0d);
    copy_halfword(dst, src, 0x0e);
    copy_halfword(dst, src, 0x10);
    copy_halfword(dst, src, 0x12);
    copy_halfword(dst, src, 0x14);
    copy_halfword(dst, src, 0x16);
    copy_halfword(dst, src, 0x18);
    copy_halfword(dst, src, 0x14);
    copy_halfword(dst, src, 0x1a);
    ptr::write_volatile(dst.add(0x1c).cast::<u32>(), ptr::read_volatile(src.add(0x1c).cast::<u32>()));
}

unsafe fn copy_byte(dst: *mut u8, src: *const u8, offset: usize) {
    dst.add(offset).write_volatile(src.add(offset).read_volatile());
}

unsafe fn copy_halfword(dst: *mut u8, src: *const u8, offset: usize) {
    ptr::write_volatile(dst.add(offset).cast::<u16>(), ptr::read_volatile(src.add(offset).cast::<u16>()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_copy(bytes: &mut [u8], dst: usize, src: usize) {
        for offset in 0..8 { bytes[dst + offset] = bytes[src + offset]; }
        for offset in 8..11 { bytes[dst + offset] = bytes[src + offset]; }
        for offset in [11, 12, 13] { bytes[dst + offset] = bytes[src + offset]; }
        for offset in [14, 16, 18, 20, 22, 24, 20, 26] {
            bytes[dst + offset] = bytes[src + offset];
            bytes[dst + offset + 1] = bytes[src + offset + 1];
        }
        for offset in 28..32 { bytes[dst + offset] = bytes[src + offset]; }
    }

    #[test]
    fn copies_all_record_bytes_without_touching_guards() {
        let mut source = [0u8; 40];
        for (index, byte) in source.iter_mut().enumerate() { *byte = index as u8 ^ 0x9d; }
        let mut destination = [0xa5u8; 40];
        unsafe { opaque_record_copy(destination.as_mut_ptr().add(4), source.as_ptr().add(4)); }
        assert_eq!(&destination[..4], &[0xa5; 4]);
        assert_eq!(&destination[4..36], &source[4..36]);
        assert_eq!(&destination[36..], &[0xa5; 4]);
    }

    #[test]
    fn overlapping_records_retain_retail_load_store_order() {
        let mut expected = [0u8; 80];
        for (index, byte) in expected.iter_mut().enumerate() { *byte = index as u8 ^ 0x53; }
        let mut actual = expected;
        reference_copy(&mut expected, 20, 16);
        unsafe { opaque_record_copy(actual.as_mut_ptr().add(20), actual.as_ptr().add(16)); }
        assert_eq!(actual, expected);
    }
}
