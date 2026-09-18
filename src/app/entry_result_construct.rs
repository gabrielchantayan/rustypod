//! `entry_result_construct` — original: `FUN_080fe500` @ **0x080fe500**
//! (44 bytes; 4 incoming direct plain `bl` calls and no predicated `bl` calls).
//!
//! Raw ARM establishes the exact extent `0x080fe500..0x080fe52c`; the next
//! word is the literal vtable address `0x089800cc`, not code. The constructor
//! installs that vtable, clears its two leading state words, state byte, and
//! auxiliary word, then records the matched entry, low 16 bits of the match
//! key, and entry kind at the target's fixed 32-bit offsets.
//!
//! # Deliberate deviations
//!
//! Target pointers remain `u32` words in the result layout even on 64-bit
//! hosts. The return value preserves the full host `result` pointer so callers
//! can continue to own the allocated object.

const ENTRY_RESULT_VTABLE: u32 = 0x0898_00cc;

/// entry_result_construct — original: `FUN_080fe500` @ **0x080fe500**.
///
/// # Safety
///
/// `result` must designate at least 27 writable bytes with target alignment.
/// `matched_entry` is recorded as a 32-bit target pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn entry_result_construct(
    result: *mut u8,
    matched_entry: *mut u8,
    match_key: u32,
    entry_kind: u8,
) -> *mut u8 {
    unsafe {
        result.cast::<u32>().write(ENTRY_RESULT_VTABLE);
        result.add(4).cast::<u32>().write(0);
        result.add(8).cast::<u32>().write(0);
        result.add(12).write(0);
        result.add(20).cast::<u32>().write(matched_entry as usize as u32);
        result.add(16).cast::<u32>().write(0);
        result.add(24).cast::<u16>().write(match_key as u16);
        result.add(26).write(entry_kind);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_target_layout_without_touching_unwritten_padding() {
        let mut result = [0xaabb_ccddu32; 7];
        let result_ptr = result.as_mut_ptr().cast();
        let returned = unsafe {
            entry_result_construct(result_ptr, 0x1234_5678usize as *mut u8, 0xfedc_9876, 0x7e)
        };

        assert_eq!(returned, result_ptr);
        assert_eq!(result, [
            0x0898_00cc,
            0,
            0,
            0xaabb_cc00,
            0,
            0x1234_5678,
            0xaa7e_9876,
        ]);
    }
}
