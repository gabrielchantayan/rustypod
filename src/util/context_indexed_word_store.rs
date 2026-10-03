//! Indexed context word store — `FUN_08240a08` @ `0x08240a08`.
//! True extent: 12 bytes, ending at the next function's push at `0x08240a14`.
//! Verified full-image A32 scan: two inbound plain BLs (0x0825181c,
//! 0x082563dc), zero predicated inbound BLs, and zero outbound calls.
//!
//! Add the index shifted left by two to the context, store the supplied word
//! at +0x38, and return the indexed base left in r0. Raw words are e0800101,
//! e5802038, e12fff1e. Callers replace one of two context entries with a
//! resolved value. No callee or runtime dependency is introduced.
//!
//! # Deliberate deviations
//!
//! Expose the residual r0 pointer explicitly despite Ghidra's void signature.
//! Host pointer arithmetic sign-extends the wrapped 32-bit byte displacement,
//! preserving target index-shift aliases without truncating host pointers.
//! No bounds checks or null guards are added.

/// # Safety
/// The context plus the wrapped signed index displacement must remain in its
/// allocation, with an aligned writable u32 at a further offset of 0x38.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_indexed_word_store(
    context: *mut u32,
    index: u32,
    value: u32,
) -> *mut u32 {
    let word_offset = (index.wrapping_shl(2) as i32 / 4) as isize;
    let indexed_base = context.wrapping_offset(word_offset);
    unsafe { indexed_base.add(14).write(value) };
    indexed_base
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_only_the_selected_word_and_returns_indexed_base() {
        for index in [0, 1, 7] {
            for value in [0, 1, 0x8000_0000, u32::MAX] {
                let mut words = [0xa5a5_5a5a; 24];
                let base = words.as_mut_ptr();
                let returned = unsafe { context_indexed_word_store(base, index, value) };
                assert_eq!(returned, base.wrapping_add(index as usize));
                let mut expected = [0xa5a5_5a5a; 24];
                expected[14 + index as usize] = value;
                assert_eq!(words, expected);
            }
        }
    }

    #[test]
    fn wraps_index_shift_and_supports_negative_displacements() {
        for (index, displacement) in [(u32::MAX, -1isize), (0x4000_0000, 0),
                                      (0x8000_0001, 1), (0xffff_fffe, -2)] {
            let mut words = [0x1234_5678; 24];
            let base = words.as_mut_ptr().wrapping_add(4);
            let returned = unsafe { context_indexed_word_store(base, index, 0) };
            assert_eq!(returned, base.wrapping_offset(displacement));
            let mut expected = [0x1234_5678; 24];
            expected[(18isize + displacement) as usize] = 0;
            assert_eq!(words, expected);
        }
    }
}
