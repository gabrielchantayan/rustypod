//! Opaque object word-0x1c predicate — `FUN_0829cf88` @ 0x0829cf88 (16
//! bytes; 3 plain `bl` call sites, no predicated calls).
//!
//! Raw ARM establishes the four-word extent 0x0829cf88..0x0829cf94: `ldr
//! r0,[r0,#0x1c]; cmp r0,#0; movne r0,#1; bx lr`; the separately entered next
//! function begins at 0x0829cf98. Full-image A32 decoding finds the three
//! inbound unconditional calls at 0x081bb19c, 0x081bb554, and 0x081cb4e4,
//! with no predicated `bl` callers and no calls in this leaf. It reads the
//! opaque object's aligned 32-bit word at offset 0x1c and returns whether it
//! is nonzero, normalized to zero or one. Deliberate deviations: none.

/// Returns whether the opaque object's word at offset 0x1c is nonzero.
///
/// # Safety
/// `object` must be valid to read an aligned `u32` at byte offset 0x1c.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_word_0x1c_is_nonzero(object: *const u8) -> u32 {
    u32::from(object.add(0x1c).cast::<u32>().read() != 0)
}

#[cfg(test)]
mod tests {
    use super::object_word_0x1c_is_nonzero;

    #[test]
    fn normalizes_zero_and_all_nonzero_word_values() {
        for value in [0, 1, 0x8000_0000, u32::MAX] {
            let mut object = [0xa5u32; 8];
            object[7] = value;

            assert_eq!(
                unsafe { object_word_0x1c_is_nonzero(object.as_ptr().cast()) },
                u32::from(value != 0)
            );
            assert!(object[..7].iter().all(|&word| word == 0xa5));
        }
    }
}
