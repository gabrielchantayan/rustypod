//! Array record initialization — `FUN_080470bc` @ 0x080470bc.
//!
//! True extent: 88 bytes, [0x080470bc, 0x08047114): 84 instruction bytes
//! and the four-byte `aray` tag literal. The next function starts with PUSH.
//! Whole-image aligned A32 decoding verifies two plain inbound BLs at
//! 0x080476f4 and 0x08047738, zero predicated inbound BLs; the body has one
//! plain BL to bzero @ 0x0805cfb4 and no predicated BLs.
//!
//! Reject NULL with -50; otherwise zero 36 bytes, install the tag and element
//! size, store the supplied backing word at +28, and set bytes +32 and +33
//! to the supplied flag and one. A zero backing word forces +32 to zero.
//! The backing word's precise interpretation is unresolved and is not
//! dereferenced. Deliberate deviations: none in behavior; LLVM codegen differs.

use crate::bzero::bzero;

/// Initializes a 36-byte array record.
///
/// # Safety
/// A non-NULL record must be four-byte aligned and writable for 36 bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn array_record_initialize(
    element_size: u32,
    backing_word: u32,
    flag: u8,
    record: *mut u8,
) -> i32 {
    if record.is_null() {
        return -50;
    }
    bzero(record, 0x24);
    record.cast::<u32>().write(0x6172_6179);
    record.cast::<u32>().add(1).write(element_size);
    record.cast::<u32>().add(7).write(backing_word);
    record.add(0x20).write(if backing_word == 0 { 0 } else { flag });
    record.add(0x21).write(1);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_rejects_without_using_supplied_words() {
        assert_eq!(unsafe {
            array_record_initialize(u32::MAX, u32::MAX, 0xff, core::ptr::null_mut())
        }, -50);
    }

    #[test]
    fn initializes_all_bytes_and_preserves_guards() {
        for element_size in [0, 4, 8, u32::MAX] {
            for backing_word in [0, 1, 0x8000_0000, u32::MAX] {
                for flag in [0, 1, 0x80, 0xff] {
                    let mut words = [0xa5a5_a5a5u32; 11];
                    let mut expected = [0u8; 36];
                    expected[..4].copy_from_slice(&0x6172_6179u32.to_le_bytes());
                    expected[4..8].copy_from_slice(&element_size.to_le_bytes());
                    expected[28..32].copy_from_slice(&backing_word.to_le_bytes());
                    expected[32] = if backing_word == 0 { 0 } else { flag };
                    expected[33] = 1;
                    unsafe {
                        let record = words.as_mut_ptr().add(1).cast::<u8>();
                        assert_eq!(array_record_initialize(element_size, backing_word, flag, record), 0);
                        assert_eq!(core::slice::from_raw_parts(record, 36), &expected);
                    }
                    assert_eq!((words[0], words[10]), (0xa5a5_a5a5, 0xa5a5_a5a5));
                }
            }
        }
    }
}
