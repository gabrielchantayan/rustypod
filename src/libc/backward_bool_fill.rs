//! backward_bool_fill — original: `FUN_08057210` @ 0x08057210 (32 bytes).
//!
//! Raw osos.dec contains eight ARM words ending in `bx lr` at 0x0805722c;
//! the next real function starts with `push` at 0x08057230. Whole-image A32
//! BL decoding finds two incoming calls: plain BL at 0x08056d98 and BLNE at
//! 0x080571dc. There are no outgoing plain or predicated BL instructions.
//!
//! Normalize value to zero or one, add len to dst, then pre-decrement the
//! cursor and store a byte while cursor >= dst (unsigned). Stores descend
//! from dst + len - 1 to dst. The original leaves dst in r0; expose that
//! preserved result even though Ghidra declares void. Both known callers
//! request zero fill (a stack buffer and an aligned arena allocation).
//!
//! Deliberate deviations: volatile stores prevent LLVM memset substitution;
//! host pointer arithmetic uses native pointer width rather than ARM's u32.
//! Wrapping cursor arithmetic retains the original unsigned termination,
//! including its lack of a NULL guard; NULL with zero length is not safe.

/// Fill bytes backwards with `0` if value is zero, otherwise `1`, returning dst.
///
/// # Safety
/// `dst` must be non-null and writable for `len` bytes. The address range must
/// not wrap. Zero length is permitted for a non-null pointer without access.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.backward_bool_fill")]
#[inline(never)]
pub unsafe extern "C" fn backward_bool_fill(dst: *mut u8, value: u32, len: u32) -> *mut u8 {
    let byte = u8::from(value != 0);
    let mut cursor = dst.wrapping_add(len as usize);
    loop {
        cursor = cursor.wrapping_sub(1);
        if (cursor as usize) < (dst as usize) {
            break;
        }
        cursor.write_volatile(byte);
    }
    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_full_word_values_and_preserves_guards_and_destination() {
        for value in [0, 1, 2, 0xff, 0x100, 0x8000_0000, u32::MAX] {
            for offset in 0..4 {
                for len in 0..=64 {
                    let mut actual = [0xa5u8; 72];
                    let mut expected = actual;
                    for byte in &mut expected[4 + offset..4 + offset + len] {
                        *byte = if value == 0 { 0 } else { 1 };
                    }
                    let dst = unsafe { actual.as_mut_ptr().add(4 + offset) };
                    let returned = unsafe { backward_bool_fill(dst, value, len as u32) };
                    assert_eq!(returned, dst);
                    assert_eq!(actual, expected, "value={value:#x}, offset={offset}, len={len}");
                }
            }
        }
    }

    #[test]
    fn zero_length_does_not_access_non_null_dangling_pointer() {
        let dst = core::ptr::NonNull::<u8>::dangling().as_ptr();
        assert_eq!(unsafe { backward_bool_fill(dst, u32::MAX, 0) }, dst);
    }
}
