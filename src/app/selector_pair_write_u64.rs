//! `selector_pair_write_u64` — original: `FUN_081d9688` @ `0x081d9688`.
//!
//! Verified size: 8 bytes, ending at the next real function, `0x081d9690`.
//! Raw words `0xe1c020f0`, `0xe12fff1e` decode as `strd r2,[r0]; bx lr`.
//! Stores the low and high selector words and preserves the destination in r0.
//! Raw A32 decoding finds 2 plain inbound BLs (0x081c834c, 0x081c88e8),
//! zero predicated BLs, and no outbound calls. Both callers construct a stack
//! selector pair for registration_handle_init.
//!
//! Deliberate deviations: expose the preserved r0 as a pointer return rather
//! than Ghidra's void. A u64 argument represents the r2:r3 pair; AAPCS skips
//! r1 for its doubleword alignment, rather than exposing Ghidra's unused r1.
//! Two aligned u32 writes express the STRD without host-endianness assumptions.
//! ARM codegen uses `stm r0,{r2,r3}` instead of STRD and a frame-pointer
//! prologue/epilogue; match.py confirms the same word stores and preserved r0.

/// Stores a 64-bit selector as low word followed by high word.
///
/// # Safety
/// `selector` must be aligned to 8 bytes and writable for two u32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selector_pair_write_u64(
    selector: *mut u32,
    value: u64,
) -> *mut u32 {
    selector.write(value as u32);
    selector.add(1).write((value >> 32) as u32);
    selector
}

#[cfg(test)]
mod tests {
    use super::selector_pair_write_u64;

    #[repr(C, align(8))]
    struct Words([u32; 6]);

    #[test]
    fn stores_low_then_high_words_preserving_guards_and_destination() {
        let mut words = Words([0xfeed_face; 6]);
        let selector = unsafe { words.0.as_mut_ptr().add(2) };
        for value in [0, u64::MAX, 0x89ab_cdef_0123_4567, 1u64 << 32, 0xffff_ffff] {
            let returned = unsafe { selector_pair_write_u64(selector, value) };
            assert_eq!(returned, selector);
            assert_eq!(words.0, [0xfeed_face, 0xfeed_face, value as u32,
                (value >> 32) as u32, 0xfeed_face, 0xfeed_face]);
        }
    }
}
